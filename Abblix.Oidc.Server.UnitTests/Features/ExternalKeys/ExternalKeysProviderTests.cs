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
/// Verifies that <see cref="ExternalKeysProvider"/> publishes only public-key material: the JWK it hands the
/// pipeline carries the store's key name as its <c>kid</c>, the intended use and algorithm, and no private half,
/// which is the exact signal the crypto seam reads to route the private operation to the store.
/// </summary>
public class ExternalKeysProviderTests
{
    [Fact]
    public async Task GetSigningKeys_PublishesPublicOnlyRs256Key_WithKidFromKeyName()
    {
        using var rsa = RSA.Create(2048);
        var provider = ProviderOver(rsa.ExportParameters(false), "sign-key");

        var key = await SingleAsync(provider.GetSigningKeys(), TestContext.Current.CancellationToken);

        Assert.Equal("sign-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Signature, key.Usage);
        Assert.Equal(SigningAlgorithms.RS256, key.Algorithm);
        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    [Fact]
    public async Task GetEncryptionKeys_PublishesPublicOnlyRsaOaep256Key_WithKidFromKeyName()
    {
        using var rsa = RSA.Create(2048);
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.GetPublicKeyAsync("enc-key", It.IsAny<CancellationToken>()))
            .ReturnsAsync(rsa.ExportParameters(false));
        var provider = new ExternalKeysProvider(store.Object, "sign-key", "enc-key");

        var key = await SingleAsync(provider.GetEncryptionKeys(), TestContext.Current.CancellationToken);

        Assert.Equal("enc-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Encryption, key.Usage);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, key.Algorithm);
        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
    }

    private static ExternalKeysProvider ProviderOver(RSAParameters publicKey, string signingKeyName)
    {
        var store = new Mock<IExternalKeyStore>();
        store.Setup(s => s.GetPublicKeyAsync(signingKeyName, It.IsAny<CancellationToken>())).ReturnsAsync(publicKey);
        return new ExternalKeysProvider(store.Object, signingKeyName, "enc-key");
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
