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

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Verifies external (key-custodian) JWE key recovery: a recipient key published public-only, whose
/// private/secret half lives behind an <see cref="IKeyCustodian"/>, decrypts through the key-recovery seam so no
/// private material enters the library. Covers RSA unwrap, symmetric AES-KW unwrap, external ECDH-ES agreement,
/// and the fail-closed rejection of producing a JWE with a public-only symmetric key - wrapping uses the local
/// secret or the recipient's public half and is never routed to a custodian.
/// </summary>
public class ExternalKeyDecryptorTests
{
    private const string Issuer = "https://auth.example.com";
    private static readonly RsaJsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

    [Fact]
    public async Task ExternalRsaKey_DecryptsInboundJwe_ViaUnwrapPort()
    {
        // A full RSA encryption key; the library holds only its public half, the private half standing behind
        // the fake custodian (an inbound encrypted request object is the canonical scenario).
        var fullKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256);
        var publicOnly = (RsaJsonWebKey)fullKey.Sanitize(includePrivateKeys: false);
        var custodian = new FakeKeyCustodian(fullKey);

        // RSA encryption uses the public half, so producing the JWE is a local operation; only the decrypt-side
        // unwrap is remote.
        var result = await RoundTripAsync(
            custodian,
            encryptionKey: publicOnly,
            decryptionKey: publicOnly,
            EncryptionAlgorithms.KeyManagement.RsaOaep256,
            EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

        AssertSucceeded(result);
        Assert.Equal(1, custodian.UnwrapCalls);
        Assert.False(publicOnly.HasPrivateKey);
    }

    [Fact]
    public async Task ExternalSymmetricKey_DecryptsInboundJwe_ViaUnwrapPort()
    {
        // A full symmetric (A256KW) key and its published public-only form (the key bytes are absent). Wrapping
        // uses the local secret, so the JWE is produced in process with the full key; only the decrypt-side
        // unwrap is remote, routed by the external (public-only) key's kid.
        var fullKey = new OctetJsonWebKey { KeyId = "ext-oct", KeyValue = CryptoRandom.GetRandomBytes(32) };
        var external = fullKey with { KeyValue = null };
        var custodian = new FakeKeyCustodian(fullKey);

        var result = await RoundTripAsync(
            custodian,
            encryptionKey: fullKey,
            decryptionKey: external,
            EncryptionAlgorithms.KeyManagement.Aes256KW,
            EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

        AssertSucceeded(result);
        Assert.Equal(1, custodian.UnwrapCalls);
        Assert.False(external.HasPrivateKey);
    }

    [Fact]
    public async Task ExternalEcKey_EcdhEs_RoundTrips_ViaAgreePort()
    {
        // A full EC key and its public-only form (x/y/crv without the private scalar d).
        var fullKey = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, EncryptionAlgorithms.KeyManagement.EcdhEs);
        var publicOnly = (EllipticCurveJsonWebKey)fullKey.Sanitize(includePrivateKeys: false);
        var custodian = new FakeKeyCustodian(fullKey);

        // ECDH-ES encryption agrees against the recipient's public half locally; only the decrypt-side agreement
        // needs the private key, so only it is remote. The KDF runs locally on the shared secret.
        var result = await RoundTripAsync(
            custodian,
            encryptionKey: publicOnly,
            decryptionKey: publicOnly,
            EncryptionAlgorithms.KeyManagement.EcdhEs,
            EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

        AssertSucceeded(result);
        Assert.Equal(1, custodian.AgreeCalls);
        Assert.False(publicOnly.HasPrivateKey);
    }

    [Fact]
    public async Task PublicOnlySymmetricKey_Encrypt_FailsClosed()
    {
        // A symmetric key has no public half: wrapping needs the secret, and wrapping is never routed to a
        // custodian, so producing a JWE with a public-only symmetric key fails closed rather than reaching for
        // absent material.
        var external = new OctetJsonWebKey { KeyId = "ext-oct", KeyValue = null };
        await using var provider = BuildProvider(new FakeKeyCustodian(external));
        var creator = provider.GetRequiredService<IJsonWebTokenCreator>();

        await Assert.ThrowsAsync<InvalidOperationException>(() => creator.IssueAsync(
            NewToken(),
            SigningKey,
            external,
            EncryptionAlgorithms.KeyManagement.Aes256KW,
            EncryptionAlgorithms.ContentEncryption.Aes256Gcm));
    }

    [Fact]
    public async Task PublicOnlyKey_WithoutCustodian_FailsClosedAtDecrypt()
    {
        // A public-only key with no custodian wired has no decryption path. Recovering the CEK for it is a
        // misconfiguration, not a decryption failure, so the seam fails loud rather than silently returning null
        // and rejecting every inbound token for the key.
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens(); // no AddKeyCustodian: LocalKeyDecryptor is the sole seam
        await using var provider = services.BuildServiceProvider();

        var seam = provider.GetRequiredService<IContentKeyDecryptor>();
        var publicOnly = (RsaJsonWebKey)JsonWebKeyFactory
            .CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256)
            .Sanitize(includePrivateKeys: false);
        var header = new JsonWebTokenHeader(new JsonObject())
        {
            Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256,
            EncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
            KeyId = publicOnly.KeyId,
        };

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await seam.DecryptKeyAsync(
            header,
            publicOnly,
            EncryptionAlgorithms.KeyManagement.RsaOaep256,
            new byte[256],
            TestContext.Current.CancellationToken));
    }

    private static async Task<Result<JsonWebToken, JwtValidationError>> RoundTripAsync(
        IKeyCustodian custodian,
        JsonWebKey encryptionKey,
        JsonWebKey decryptionKey,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm)
    {
        await using var provider = BuildProvider(custodian);

        var creator = provider.GetRequiredService<IJsonWebTokenCreator>();
        var jwe = await creator.IssueAsync(
            NewToken(), SigningKey, encryptionKey, keyManagementAlgorithm, contentEncryptionAlgorithm);

        var validator = provider.GetRequiredService<IJsonWebTokenValidator>();
        return await validator.ValidateAsync(jwe, new ValidationParameters
        {
            Options = ValidationOptions.ValidateIssuer | ValidationOptions.RequireSignedTokens,
            ValidateIssuer = iss => Task.FromResult(iss == Issuer),
            ResolveIssuerSigningKeys = _ => new[] { SigningKey.Sanitize(false) }.ToAsyncEnumerable(),
            ResolveTokenDecryptionKeys = _ => new[] { decryptionKey }.ToAsyncEnumerable(),
        });
    }

    private static ServiceProvider BuildProvider(IKeyCustodian custodian)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddKeyCustodian(custodian); // the host wires its key custodian into both seams
        return services.BuildServiceProvider();
    }

    private static JsonWebToken NewToken() => new()
    {
        Header = { Type = "JWT" },
        Payload =
        {
            Subject = "user-1",
            Issuer = Issuer,
            Audiences = ["test-audience"],
            ExpiresAt = TimeProvider.System.GetUtcNow().AddHours(1),
        },
    };

    private static void AssertSucceeded(Result<JsonWebToken, JwtValidationError> result)
        => Assert.True(
            result.TryGetSuccess(out _),
            result.TryGetFailure(out var error) ? $"{error.Error} - {error.ErrorDescription}" : "Validation failed");

    /// <summary>
    /// Stands in for an HSM/KMS/vault: holds the private/secret material the library never sees and performs the
    /// decrypt-side key-recovery operations that need it, recording how many times each was invoked.
    /// </summary>
    private sealed class FakeKeyCustodian(JsonWebKey fullKey) : IKeyCustodian
    {
        public int UnwrapCalls { get; private set; }
        public int AgreeCalls { get; private set; }

        // This custodian holds only encryption keys, so the library never routes a signing operation here.
        public ValueTask<byte[]> SignAsync(string kid, string algorithm, byte[] data, CancellationToken cancellationToken)
            => throw new NotSupportedException("This decryption custodian holds no signing keys.");

        public ValueTask<byte[]?> UnwrapKeyAsync(
            string kid,
            string algorithm,
            JsonWebTokenHeader header,
            byte[] encryptedKey,
            CancellationToken cancellationToken)
        {
            UnwrapCalls++;
            var cek = fullKey switch
            {
                RsaJsonWebKey rsaKey => RsaDecrypt(rsaKey, algorithm, encryptedKey),

                OctetJsonWebKey { KeyValue: { } secret }
                    => AesKeyWrap.TryUnwrap(secret, encryptedKey, out var unwrapped) ? unwrapped : null,

                _ => null,
            };
            return new ValueTask<byte[]?>(cek);
        }

        public ValueTask<byte[]> AgreeKeyAsync(
            string kid,
            string algorithm,
            JsonWebKey ephemeralPublicKey,
            CancellationToken cancellationToken)
        {
            AgreeCalls++;
            using var recipient = ((EllipticCurveJsonWebKey)fullKey).ToEcdh();
            using var ephemeral = ((EllipticCurveJsonWebKey)ephemeralPublicKey).ToEcdh();
            return new ValueTask<byte[]>(recipient.DeriveRawSecretAgreement(ephemeral.PublicKey));
        }

        private static byte[]? RsaDecrypt(RsaJsonWebKey key, string algorithm, byte[] encryptedKey)
        {
            var padding = algorithm switch
            {
                EncryptionAlgorithms.KeyManagement.RsaOaep => RSAEncryptionPadding.OaepSHA1,
                EncryptionAlgorithms.KeyManagement.RsaOaep256 => RSAEncryptionPadding.OaepSHA256,
                EncryptionAlgorithms.KeyManagement.Rsa1_5 => RSAEncryptionPadding.Pkcs1,
                _ => null,
            };
            if (padding == null)
                return null;

            try
            {
                using var rsa = key.ToRsa();
                return rsa.Decrypt(encryptedKey, padding);
            }
            catch (CryptographicException)
            {
                return null;
            }
        }
    }
}
