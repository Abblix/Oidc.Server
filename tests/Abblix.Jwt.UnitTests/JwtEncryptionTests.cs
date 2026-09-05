// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
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
        // RSA1_5 is deliberately not part of the AddJsonWebTokens defaults - the legacy-interop
        // round-trip and Bleichenbacher-mitigation tests below opt in explicitly
        services.AddRsaPkcs1KeyManagement();
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

            // This case measures the expiry itself, so it tolerates no clock offset: the default
            // window would keep the token usable past the instant under test.
            ClockSkew = Abblix.Jwt.ClockSkew.None,
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
    /// Verifies RSA1_5 (RSAES-PKCS1-v1_5) round-trips once a host opts in via
    /// <c>AddRsaPkcs1KeyManagement</c> (this class's service provider does): a JWE encrypted with it
    /// decrypts correctly and the algorithm is advertised. The Bleichenbacher oracle that PKCS1-v1.5
    /// would otherwise expose is closed by the RFC 7516 section 11.5 random-CEK mitigation (see
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
    /// Verifies the RFC 7516 section 11.5 mitigation: when the encrypted Content Encryption Key cannot be
    /// decrypted (here the encrypted-key segment is replaced with random bytes), the decryptor
    /// substitutes a random CEK and still runs the AEAD step, which fails the authentication tag.
    /// The outcome is a uniform invalid_token result - no exception and no distinct error that
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
    /// <summary>
    /// Verifies the RFC 7516 section 11.5 mitigation closes the Bleichenbacher timing oracle even when RSA1_5
    /// decryption SUCCEEDS with structurally valid PKCS#1 v1.5 padding but produces a wrong-length CEK.
    /// A wrong-length CEK would make the content decryptor fast-fail on its length check before running
    /// the AEAD step, whereas the padding-invalid branch substitutes a correct-length random CEK and runs
    /// the full step - an observable difference in work. The JWE decryptor must therefore also substitute
    /// a random CEK on a length mismatch, so the content decryptor always receives a correct-length key.
    /// </summary>
    [Fact]
    [SuppressMessage("Security", "S5542:Encryption algorithms should be used with secure mode and padding scheme",
        Justification = "The test deliberately crafts an RSA1_5/PKCS1 encrypted_key to verify the server's " +
                        "Bleichenbacher / random-CEK mitigation on the insecure algorithm it must still tolerate.")]
    public async Task Rsa1_5_ValidPaddingWrongLengthCek_StillRunsAeadOnCorrectLengthKey()
    {
        // A spy content decryptor records the CEK length the JWE decryptor hands it and reports the
        // A256GCM key size so the mitigation's length comparison targets 32 bytes.
        var spy = new KeyLengthRecordingEncryptor(keySizeInBytes: 32);

        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        // Appended after AddJsonWebTokens so keyed last-wins resolution routes A256GCM to the spy.
        services.AddKeyedSingleton<IContentEncryptionAlgorithm>(EncryptionAlgorithms.ContentEncryption.Aes256Gcm, spy);
        await using var provider = services.BuildServiceProvider();

        var encKey = (RsaJsonWebKey)encryptionKey;

        // Craft an encrypted_key that RSA1_5-decrypts to valid padding but a 5-byte (wrong-length) CEK.
        byte[] craftedEncryptedKey;
        using (var rsa = encKey.ToRsa())
            craftedEncryptedKey = rsa.Encrypt(new byte[] { 1, 2, 3, 4, 5 }, RSAEncryptionPadding.Pkcs1);

        var header = new JsonObject
        {
            [JwtClaimTypes.Algorithm] = EncryptionAlgorithms.KeyManagement.Rsa1_5,
            [JwtClaimTypes.EncryptionAlgorithm] = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
            [JwtClaimTypes.KeyId] = encKey.KeyId,
        };

        var jwtParts = new[]
        {
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString())),
            Base64Url.EncodeToString(craftedEncryptedKey),
            Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(12)),
            Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(16)),
            Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(16)),
        };

        var encryptor = provider.GetRequiredService<IJsonWebTokenEncryptor>();
        var result = await encryptor.DecryptAsync(
            jwtParts,
            new JsonWebKey[] { encKey }.ToAsyncEnumerable(),
            TestContext.Current.CancellationToken);

        // The content decryptor must run on a correct-length CEK (32 bytes for A256GCM), not on the
        // 5-byte value RSA1_5 decrypted - otherwise the fast length-fail leaks PKCS1 padding validity.
        Assert.Equal(32, spy.LastKeyLength);
        Assert.True(result.TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
    }

    [SuppressMessage("Major Code Smell", "S1172:Unused method parameters should be removed",
        Justification = "Signatures are mandated by IContentEncryptionAlgorithm; this spy records only the CEK length.")]
    [SuppressMessage("Minor Code Smell", "S2325:Methods and properties that don't access instance data should be static",
        Justification = "Explicit IContentEncryptionAlgorithm interface implementation cannot be static.")]
    private sealed class KeyLengthRecordingEncryptor(int keySizeInBytes) : IContentEncryptionAlgorithm
    {
        public int LastKeyLength { get; private set; } = -1;

        public string Algorithm => EncryptionAlgorithms.ContentEncryption.Aes256Gcm;

        public int KeySizeInBytes { get; } = keySizeInBytes;

        public EncryptedData Encrypt(byte[] contentEncryptionKey, byte[] plaintext, byte[] additionalAuthenticatedData)
            => throw new NotSupportedException();

        public bool TryDecrypt(
            byte[] contentEncryptionKey,
            EncryptedData encryptedData,
            byte[] additionalAuthenticatedData,
            [NotNullWhen(true)] out byte[]? plaintext)
        {
            LastKeyLength = contentEncryptionKey.Length;
            plaintext = null;
            return false;
        }
    }
}
