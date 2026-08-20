// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The <c>crit</c> parameter on the OUTER protected header of a JWE. RFC 7516 Section 4.1.13
/// defines it by pointing at the JWS definition, so the rules are the same rules, but until
/// 2026-07-20 the library checked only the inner JWS header after decryption and a critical
/// extension declared on the envelope was silently ignored.
/// </summary>
/// <remarks>
/// The outer header is built inside the encryptor with no injection point, so these tests issue a
/// real JWE and then rewrite its first part. That also changes the AEAD associated data, which is
/// exactly why every assertion here names <c>crit</c> in the message rather than merely checking
/// the error category: without the check under test, the same tokens are rejected too, but for the
/// wrong reason and only after key material has been touched. The control at the end proves the
/// unmodified token still decrypts, so the splicing is not what these tests are measuring.
/// </remarks>
public class JweCriticalHeaderTests
{
    private const string IssuerUri = "https://issuer.example.com";
    private const string TestAudience = "test-audience";
    private const string ExtensionName = "my-ext";

    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
    private static readonly JsonWebKey EncryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);

    private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

    private static IServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    private static async Task<string> IssueJwe()
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload =
            {
                Issuer = IssuerUri,
                Audiences = [TestAudience],
                ExpiresAt = TimeProvider.System.GetUtcNow().AddHours(1),
            },
        };

        var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
        return await creator.IssueAsync(token, SigningKey, EncryptionKey);
    }

    /// <summary>
    /// Rewrites the JWE protected header, applying <paramref name="edit"/> to the parsed object.
    /// </summary>
    private static async Task<string> IssueJweWithHeader(Action<JsonObject> edit)
    {
        var parts = (await IssueJwe()).Split('.');
        var header = JsonNode.Parse(
            Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0])))!.AsObject();

        edit(header);

        parts[0] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));
        return string.Join('.', parts);
    }

    private static Task<Result<JsonWebToken, JwtValidationError>> Validate(string jwt)
    {
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        return validator.ValidateAsync(jwt, new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
            ResolveTokenDecryptionKeys = _ => EncryptionKey.ToAsync(),
        });
    }

    private static async Task AssertRejectedForCrit(string jwt)
    {
        var result = await Validate(jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("crit", error.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The headline case: an extension nobody registered, declared critical on the envelope.
    /// RFC 7515 Section 4.1.11, which RFC 7516 Section 4.1.13 adopts, says the token is invalid
    /// if a listed parameter is not understood - and this library understands none.
    /// </summary>
    [Fact]
    public async Task UnknownCriticalExtension_Rejected()
    {
        var jwt = await IssueJweWithHeader(header =>
        {
            header[JwtClaimTypes.Critical] = new JsonArray(ExtensionName);
            header[ExtensionName] = "whatever";
        });

        await AssertRejectedForCrit(jwt);
    }

    /// <summary>
    /// "Producers MUST NOT use the empty list" (RFC 7515 Section 4.1.11).
    /// </summary>
    [Fact]
    public async Task EmptyCriticalList_Rejected()
    {
        var jwt = await IssueJweWithHeader(header => header[JwtClaimTypes.Critical] = new JsonArray());

        await AssertRejectedForCrit(jwt);
    }

    /// <summary>
    /// A name listed twice.
    /// </summary>
    [Fact]
    public async Task DuplicateCriticalName_Rejected()
    {
        var jwt = await IssueJweWithHeader(header =>
        {
            header[JwtClaimTypes.Critical] = new JsonArray(ExtensionName, ExtensionName);
            header[ExtensionName] = "whatever";
        });

        await AssertRejectedForCrit(jwt);
    }

    /// <summary>
    /// A name declared critical but absent from the header it points into.
    /// </summary>
    [Fact]
    public async Task DanglingCriticalName_Rejected()
    {
        var jwt = await IssueJweWithHeader(header => header[JwtClaimTypes.Critical] = new JsonArray(ExtensionName));

        await AssertRejectedForCrit(jwt);
    }

    /// <summary>
    /// A registered JWE parameter may not be declared critical: <c>crit</c> names extensions, and
    /// these are not extensions. <c>zip</c> is registered by RFC 7516 Section 4.1.3 and belongs to
    /// the JWE set specifically, so it also proves the JWE list is wider than the JWS one.
    /// </summary>
    [Theory]
    [InlineData(JwtClaimTypes.CompressionAlgorithm)]
    [InlineData(JwtClaimTypes.EphemeralPublicKey)]
    [InlineData(JwtClaimTypes.Pbes2SaltInput)]
    [InlineData(JwtClaimTypes.Algorithm)]
    public async Task RegisteredParameterDeclaredCritical_Rejected(string reservedName)
    {
        var jwt = await IssueJweWithHeader(header =>
        {
            header[JwtClaimTypes.Critical] = new JsonArray(reservedName);
            header[reservedName] = "whatever";
        });

        await AssertRejectedForCrit(jwt);
    }

    /// <summary>
    /// A <c>crit</c> that is not an array of strings must come back as a verdict, not as an
    /// exception escaping the validator on attacker-supplied input.
    /// </summary>
    [Theory]
    [InlineData("42")]
    [InlineData("\"my-ext\"")]
    [InlineData("[\"a\", 42]")]
    [InlineData("{}")]
    public async Task MalformedCritical_RejectedWithoutThrowing(string criticalJson)
    {
        var jwt = await IssueJweWithHeader(header => header[JwtClaimTypes.Critical] = JsonNode.Parse(criticalJson));

        await AssertRejectedForCrit(jwt);
    }

    /// <summary>
    /// The control. An untouched JWE still round-trips, so the rejections above are about
    /// <c>crit</c> and not about the envelope being rewritten.
    /// </summary>
    [Fact]
    public async Task JweWithoutCritical_Validates()
    {
        var result = await Validate(await IssueJwe());

        Assert.True(result.TryGetSuccess(out var token));
        Assert.Equal(IssuerUri, token.Payload.Issuer);
    }
}
