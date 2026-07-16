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

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ExternalKeys;

/// <summary>
/// Verifies that <see cref="ExternalKeysProvider"/> stamps the configured kid, use and algorithm onto the bare
/// public key the custodian returns, keeping its runtime type (RSA or EC), and never publishes private material.
/// </summary>
public class ExternalKeysProviderTests
{
    [Fact]
    public async Task GetSigningKeys_StampsConfiguredAlgorithm_OnAnRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var provider = ProviderPublishing(
            "sign-key", new RsaJsonWebKey().Apply(rsa.ExportParameters(false)), SigningAlgorithms.PS256);

        var key = await SingleAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        Assert.IsType<RsaJsonWebKey>(key);
        Assert.Equal("sign-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Signature, key.Usage);
        Assert.Equal(SigningAlgorithms.PS256, key.Algorithm);
        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public async Task GetSigningKeys_StampsConfiguredAlgorithm_OnAnEcKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var provider = ProviderPublishing(
            "sign-key", new EllipticCurveJsonWebKey().Apply(ecdsa.ExportParameters(false)), SigningAlgorithms.ES256);

        var key = await SingleAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        // The provider keeps the store's key type; an EC store key is published as an EC JWK.
        Assert.IsType<EllipticCurveJsonWebKey>(key);
        Assert.Equal("sign-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Signature, key.Usage);
        Assert.Equal(SigningAlgorithms.ES256, key.Algorithm);
        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public async Task GetEncryptionKeys_StampsConfiguredAlgorithm()
    {
        using var rsa = RSA.Create(2048);
        var store = new Mock<IKeyCustodian>();
        store.Setup(s => s.GetPublicKeyAsync("enc-key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new RsaJsonWebKey().Apply(rsa.ExportParameters(false)));
        var provider = new ExternalKeysProvider(store.Object, new ExternalKeyConfiguration(
            "sign-key", SigningAlgorithms.RS256, "enc-key", EncryptionAlgorithms.KeyManagement.RsaOaep));

        var key = await SingleAsync(provider.GetEncryptionKeys(), TestContext.Current.CancellationToken);

        Assert.Equal("enc-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Encryption, key.Usage);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep, key.Algorithm);
        Assert.False(key.HasPrivateKey);
    }

    private static ExternalKeysProvider ProviderPublishing(string signingKeyName, JsonWebKey publicKey, string signingAlgorithm)
    {
        var store = new Mock<IKeyCustodian>();
        store.Setup(s => s.GetPublicKeyAsync(signingKeyName, It.IsAny<CancellationToken>())).ReturnsAsync(publicKey);
        return new ExternalKeysProvider(store.Object, new ExternalKeyConfiguration(
            signingKeyName, signingAlgorithm, "enc-key", EncryptionAlgorithms.KeyManagement.RsaOaep256));
    }

    private static async Task<JsonWebKey> SingleAsync(IAsyncEnumerable<JsonWebKey> keys, CancellationToken ct)
    {
        JsonWebKey? single = null;
        await foreach (var key in keys.WithCancellation(ct))
        {
            Assert.Null(single); // the provider publishes exactly one key per usage
            single = key;
        }

        Assert.NotNull(single);
        return single;
    }
}
