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

using System.Buffers.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for JWT (JSON Web Token) encryption and signing full lifecycle.
/// Tests the complete cycle of creating, signing, encrypting, decrypting, validating, and verifying JWTs,
/// including expiration handling per RFC 7519 (JWT), RFC 7515 (JWS), and RFC 7516 (JWE).
/// </summary>
public class JwtEncryptionTests
{
    private static readonly JsonWebKey encryptionKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Enc);
    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Sig);

    private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

    private static IServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Verifies the complete JWT lifecycle: create → sign → encrypt → decrypt → validate → verify → expire.
    /// Tests that:
    /// - JWT can be created with header (algorithm RS256) and payload (claims, timestamps)
    /// - Token is signed with RSA private key (JWS - RFC 7515)
    /// - Token is encrypted with RSA public key (JWE - RFC 7516)
    /// - Token can be decrypted with RSA private key
    /// - Token signature validates correctly
    /// - All claims round-trip correctly (simple, structured objects, arrays)
    /// - Token expiration is enforced after ExpiresAt timestamp
    /// </summary>
    [Fact]
    public async Task JwtFullCycleTest()
    {
        var issuedAt = DateTimeOffset.UtcNow;
        var expiresIn = TimeSpan.FromSeconds(10);

        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = {
                JwtId = Guid.NewGuid().ToString("N"),
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + expiresIn,
                Issuer = "abblix.com",
                Audiences = [nameof(JwtFullCycleTest)],
                ["test"] = "value",
                ["address"] = new JsonObject
                {
                    { "street", "123 Main St" },
                    { "city", "Springfield" },
                    { "state", "IL" },
                    { "zip", "62701" },
                },
                ["colors"] = new JsonArray("red", "green", "blue"),
            },
        };

        var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
        var jwt = await creator.IssueAsync(token, SigningKey, encryptionKey);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = aud => Task.FromResult(token.Payload.Audiences.SequenceEqual(aud)),
            ValidateIssuer = iss => Task.FromResult(iss == token.Payload.Issuer),
            ResolveTokenDecryptionKeys = _ => new [] { encryptionKey }.ToAsyncEnumerable(),
            ResolveIssuerSigningKeys = _ => new [] { SigningKey }.ToAsyncEnumerable(),
        };

        var validatorResult = await validator.ValidateAsync(jwt, parameters);
        Assert.True(validatorResult.TryGetSuccess(out var result));
        var expectedClaims = ExtractClaims(token).OrderBy(c => c.Key).ToList();
        var actualClaims = ExtractClaims(result).OrderBy(c => c.Key).ToList();
        Assert.Equal(expectedClaims, actualClaims);

        var arrayValues = result.Payload.Json.GetArrayOfStrings("colors");
        Assert.Equal(["red", "green", "blue"], arrayValues);

        var address = result.Payload.Json["address"]?.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
        Assert.Equal("{\"street\":\"123 Main St\",\"city\":\"Springfield\",\"state\":\"IL\",\"zip\":\"62701\"}", address);

        await Task.Delay(expiresIn, TestContext.Current.CancellationToken);

        var result2 = await validator.ValidateAsync(jwt, parameters);
        Assert.True(result2.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Contains("Token has expired", error.ErrorDescription);
    }

    /// <summary>
    /// Verifies the self-reporting discovery contract: registering the encryptors via
    /// <c>AddJsonWebTokens</c> not only wires up decryption but also surfaces the supported
    /// JWE algorithms through the validator, so adding an encryptor automatically advertises
    /// its algorithm without a separate registration step.
    /// </summary>
    [Fact]
    public void RegisteredEncryptors_SelfReportSupportedAlgorithms()
    {
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();

        Assert.Contains(EncryptionAlgorithms.KeyManagement.RsaOaep256, validator.EncryptionAlgorithmsSupported);
        Assert.Contains(EncryptionAlgorithms.KeyManagement.Aes256Gcmkw, validator.EncryptionAlgorithmsSupported);
        Assert.Contains(EncryptionAlgorithms.KeyManagement.Dir, validator.EncryptionAlgorithmsSupported);

        Assert.Contains(EncryptionAlgorithms.ContentEncryption.Aes256Gcm, validator.EncryptionMethodsSupported);
        Assert.Contains(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, validator.EncryptionMethodsSupported);
    }

    /// <summary>
    /// Verifies RSA1_5 (RSAES-PKCS1-v1_5) round-trips: it is kept for backward compatibility, and a
    /// JWE encrypted with it decrypts correctly. The Bleichenbacher oracle that PKCS1-v1.5 would
    /// otherwise expose is closed by the RFC 7516 §11.5 random-CEK mitigation (see
    /// <see cref="TamperedEncryptedKey_IsRejected_Uniformly"/>).
    /// </summary>
    [Fact]
    public async Task Rsa1_5_RoundTrips()
    {
        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        Assert.Contains(EncryptionAlgorithms.KeyManagement.Rsa1_5, validator.EncryptionAlgorithmsSupported);

        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Issuer = "abblix.com", Audiences = [nameof(Rsa1_5_RoundTrips)], ["test"] = "value" },
        };

        var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
        var jwe = await creator.IssueAsync(
            token, SigningKey, encryptionKey,
            keyEncryptionAlgorithm: EncryptionAlgorithms.KeyManagement.Rsa1_5);

        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveTokenDecryptionKeys = _ => new[] { encryptionKey }.ToAsyncEnumerable(),
            ResolveIssuerSigningKeys = _ => new[] { SigningKey }.ToAsyncEnumerable(),
        };

        var result = await validator.ValidateAsync(jwe, parameters);

        Assert.True(result.TryGetSuccess(out var validated));
        Assert.Equal("value", validated.Payload.Json["test"]?.GetValue<string>());
    }

    /// <summary>
    /// Verifies the RFC 7516 §11.5 mitigation: when the encrypted Content Encryption Key cannot be
    /// decrypted (here the encrypted-key segment is replaced with random bytes), the decryptor
    /// substitutes a random CEK and still runs the AEAD step, which fails the authentication tag.
    /// The outcome is a uniform invalid_token result — no exception and no distinct error that
    /// could serve as a padding oracle.
    /// </summary>
    [Fact]
    public async Task TamperedEncryptedKey_IsRejected_Uniformly()
    {
        var token = new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.RS256 },
            Payload = { Issuer = "abblix.com", Audiences = [nameof(TamperedEncryptedKey_IsRejected_Uniformly)] },
        };

        var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
        var jwe = await creator.IssueAsync(token, SigningKey, encryptionKey);

        // Replace the encrypted-key segment (index 1) with random bytes of the same length so the
        // CEK decryption fails while the JWE stays structurally valid.
        var parts = jwe.Split('.');
        var originalKeyLength = Base64Url.DecodeFromChars(parts[1]).Length;
        parts[1] = Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(originalKeyLength));
        var tampered = string.Join('.', parts);

        var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
        var parameters = new ValidationParameters
        {
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveTokenDecryptionKeys = _ => new[] { encryptionKey }.ToAsyncEnumerable(),
            ResolveIssuerSigningKeys = _ => new[] { SigningKey }.ToAsyncEnumerable(),
        };

        var result = await validator.ValidateAsync(tampered, parameters);

        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    private static IEnumerable<(string Key, string?)> ExtractClaims(JsonWebToken token)
        => from claim in token.Payload.Json
            select (claim.Key, claim.Value?.ToJsonString());
}
