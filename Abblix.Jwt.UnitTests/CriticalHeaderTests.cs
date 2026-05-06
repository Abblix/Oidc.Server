// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for the JWS 'crit' header parameter validation per RFC 7515 §4.1.11.
/// Tokens are signed with a real RSA key so the signature step passes; the focus is on the
/// post-signature 'crit' validation pass that decides whether the JOSE header itself is acceptable.
/// </summary>
public class CriticalHeaderTests
{
    private const string IssuerUri = "https://issuer.example.com";
    private const string TestAudience = "test-audience";
    private const string ExtensionName = "b64";

    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

    /// <summary>
    /// A JWS without 'crit' validates exactly as before; the new pass is a no-op when 'crit'
    /// is absent, which is the overwhelming common case.
    /// </summary>
    [Fact]
    public async Task TokenWithoutCrit_Validates()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(sp, criticalNode: null, extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// Per RFC 7515 §4.1.11 a producer MUST NOT use the empty list as 'crit'. The validator
    /// rejects malformed input as recipient-MAY.
    /// </summary>
    [Fact]
    public async Task TokenWithEmptyCrit_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(sp, criticalNode: new JsonArray(), extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// 'crit' MUST NOT include header parameter names defined by RFC 7515 / JWA. 'alg' is
    /// always present in the JOSE header but is reserved, so listing it in 'crit' is rejected.
    /// </summary>
    [Theory]
    [InlineData(JwtClaimTypes.Algorithm)]
    [InlineData(JwtClaimTypes.KeyId)]
    [InlineData(JwtClaimTypes.Type)]
    [InlineData(JwtClaimTypes.Critical)]
    [InlineData(JwtClaimTypes.X509Sha256Thumbprint)]
    public async Task TokenWithReservedNameInCrit_FailsValidation(string reservedName)
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)reservedName),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// 'crit' MUST NOT contain duplicate names.
    /// </summary>
    [Fact]
    public async Task TokenWithDuplicateNamesInCrit_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName, (JsonNode)ExtensionName),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// Every name in 'crit' MUST also appear as a header parameter in the JOSE header.
    /// A name in 'crit' but absent from the header is a "dangling" reference.
    /// </summary>
    [Fact]
    public async Task TokenWithCritNameNotPresentInHeader_FailsValidation()
    {
        var sp = CreateServiceProvider(new StaticHandler(ExtensionName));
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// A 'crit' name that names an extension the host has not registered MUST be rejected
    /// (RFC 7515 §4.1.11: "If any of the listed extension Header Parameters are not understood
    /// and supported by the recipient, then the JWS is invalid").
    /// </summary>
    [Fact]
    public async Task TokenWithUnknownExtensionInCrit_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: false);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// When the host has registered a handler for the 'crit' name and the named header is
    /// present in the JOSE header, validation succeeds. This is the happy path that lets a
    /// future RFC 7797 / DPoP-style extension be wired into the validator without library changes.
    /// </summary>
    [Fact]
    public async Task TokenWithRegisteredExtensionInCrit_Validates()
    {
        var sp = CreateServiceProvider(new StaticHandler(ExtensionName));
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName),
            extensionValue: false);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetSuccess(out _));
    }

    /// <summary>
    /// 'crit' MUST be a JSON array; a scalar value is malformed.
    /// </summary>
    [Fact]
    public async Task TokenWithCritNotAnArray_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(sp, criticalNode: 42, extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    /// <summary>
    /// 'crit' MUST contain only string values; a non-string array element is malformed.
    /// </summary>
    [Fact]
    public async Task TokenWithCritContainingNonString_FailsValidation()
    {
        var sp = CreateServiceProvider();
        var jwt = await IssueTokenWithHeader(
            sp,
            criticalNode: new JsonArray((JsonNode)ExtensionName, 42),
            extensionValue: null);

        var result = await Validate(sp, jwt);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    private static IServiceProvider CreateServiceProvider(params ICriticalHeaderHandler[] handlers)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        foreach (var handler in handlers)
            services.AddSingleton(handler);
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    private static async Task<string> IssueTokenWithHeader(
        IServiceProvider sp,
        JsonNode? criticalNode,
        JsonNode? extensionValue)
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

        if (criticalNode is not null)
            token.Header.Json[JwtClaimTypes.Critical] = criticalNode;
        if (extensionValue is not null)
            token.Header.Json[ExtensionName] = extensionValue;

        var creator = sp.GetRequiredService<IJsonWebTokenCreator>();
        return await creator.IssueAsync(token, SigningKey);
    }

    private static async Task<Result<JsonWebToken, JwtValidationError>> Validate(IServiceProvider sp, string jwt)
    {
        var validator = sp.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => new[] { SigningKey }.ToAsyncEnumerable(),
            Options = ValidationOptions.Default,
        };
        return await validator.ValidateAsync(jwt, parameters);
    }

    private sealed class StaticHandler(string name) : ICriticalHeaderHandler
    {
        public string HeaderName { get; } = name;
    }
}
