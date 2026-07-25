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

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Verifies external (key-custodian) signing: a signing key published public-only, whose private half lives
/// behind a host <c>IKeyCustodian</c> registered with <c>AddKeyCustodian</c>, produces a token that
/// validates against the public key - proving the library never loads private material yet issues a
/// verifiable signature. Also verifies the fail-closed behaviour when a public-only key has no external
/// signer wired.
/// </summary>
public class ExternalSignerTests
{
    private const string Issuer = "https://auth.example.com";

    [Fact]
    public async Task PublicOnlySigningKey_SignsViaExternalSigner_AndValidatesWithPublicKey()
    {
        // A full RSA signing key. The library is configured with only its PUBLIC half; the private half
        // stands behind a fake external custodian (an HSM/KMS/vault stand-in).
        var fullKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var publicOnlyKey = (RsaJsonWebKey)fullKey.Sanitize(includePrivateKeys: false);
        Assert.False(publicOnlyKey.HasPrivateKey);

        var custodian = new FakeCustodian(fullKey);

        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddKeyCustodian(custodian); // the host wires its key custodian into both seams
        await using var provider = services.BuildServiceProvider();

        var token = new JsonWebToken
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

        var creator = provider.GetRequiredService<IJsonWebTokenCreator>();
        var jwt = await creator.IssueAsync(token, publicOnlyKey);

        // The signature was produced by the external custodian, addressed by the key's own kid and algorithm -
        // and the library never held private material for that key.
        Assert.Equal(1, custodian.CallCount);
        Assert.Equal(publicOnlyKey.KeyId, custodian.LastKid);
        Assert.Equal(SigningAlgorithms.RS256, custodian.LastAlgorithm);
        Assert.False(publicOnlyKey.HasPrivateKey);

        // The externally-produced signature verifies against the published public key.
        var validator = provider.GetRequiredService<IJsonWebTokenValidator>();
        var result = await validator.ValidateAsync(jwt, new ValidationParameters
        {
            Options = ValidationOptions.ValidateIssuer | ValidationOptions.RequireSignedTokens,
            ValidateIssuer = iss => Task.FromResult(iss == Issuer),
            ResolveIssuerSigningKeys = _ => new JsonWebKey[] { publicOnlyKey }.ToAsyncEnumerable(),
        });

        Assert.True(
            result.TryGetSuccess(out _),
            result.TryGetFailure(out var error)
                ? $"Validation failed: {error.Error} - {error.ErrorDescription}"
                : "Validation failed");
    }

    [Fact]
    public async Task PublicOnlySigningKey_WithoutExternalSigner_FailsClosed()
    {
        // A public-only signing key with no external signer wired cannot sign: the seam fails closed rather
        // than silently emitting an unsigned or empty signature.
        var publicOnlyKey = (RsaJsonWebKey)JsonWebKeyFactory
            .CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            .Sanitize(includePrivateKeys: false);

        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens(); // no external signer wired
        await using var provider = services.BuildServiceProvider();

        var token = new JsonWebToken
        {
            Header = { Type = "JWT" },
            Payload = { Subject = "user-1", Issuer = Issuer },
        };

        var creator = provider.GetRequiredService<IJsonWebTokenCreator>();
        await Assert.ThrowsAsync<InvalidOperationException>(() => creator.IssueAsync(token, publicOnlyKey));
    }

    /// <summary>
    /// Stands in for an HSM/KMS/vault: holds the private half the library never sees and signs with it,
    /// recording how it was called so the test can assert the routing addressed it by kid and algorithm. It is
    /// wired via <c>AddKeyCustodian</c>; holding no decryption keys, it leaves unwrap and agree unreachable.
    /// </summary>
    private sealed class FakeCustodian(RsaJsonWebKey privateKey) : IKeyCustodian
    {
        public int CallCount { get; private set; }
        public string? LastKid { get; private set; }
        public string? LastAlgorithm { get; private set; }

        public Task<byte[]> SignAsync(string keyId, string algorithm, byte[] data, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            LastKid = keyId;
            LastAlgorithm = algorithm;

            // RS256 is RSASSA-PKCS1-v1_5 over SHA-256; the library verifies this against the public key.
            using var rsa = privateKey.ToRsa();
            return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        public Task<byte[]?> UnwrapKeyAsync(
            string keyId, string algorithm, JsonWebTokenHeader header, byte[] encryptedKey, CancellationToken cancellationToken)
            => throw new NotSupportedException("This signing custodian holds no decryption keys.");

        public Task<byte[]> AgreeKeyAsync(
            string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
            => throw new NotSupportedException("This signing custodian holds no decryption keys.");

        public async IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
            string keyName, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
            yield return new KeyVersion(privateKey.Sanitize(includePrivateKeys: false), DateTimeOffset.MinValue);
        }
    }
}
