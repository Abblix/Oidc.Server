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

using System.Net;
using System.Security.Cryptography;
using Abblix.Jwt;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Verifies that <see cref="VaultKeysProvider"/> publishes only public-key material: the JWK it hands the
/// pipeline carries the Transit key name as its <c>kid</c>, the intended use and algorithm, and no private half,
/// which is the exact signal the crypto seam reads to route the private operation to Vault.
/// </summary>
public class VaultKeysProviderTests
{
    private static VaultKeysProvider ProviderPublishing(string pem, VaultTransitOptions options)
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK,
            new
            {
                data = new
                {
                    latest_version = 1,
                    keys = new Dictionary<string, object> { ["1"] = new { public_key = pem } },
                },
            }));
        var client = new VaultTransitClient(new HttpClient(handler)
        {
            BaseAddress = new Uri("http://vault.test/v1/transit/"),
        });
        return new VaultKeysProvider(client, Options.Create(options));
    }

    [Fact]
    public async Task GetSigningKeys_PublishesPublicOnlyRs256Key_WithKidFromKeyName()
    {
        using var rsa = RSA.Create(2048);
        var provider = ProviderPublishing(rsa.ExportSubjectPublicKeyInfoPem(),
            new VaultTransitOptions { SigningKeyName = "sign-key", EncryptionKeyName = "enc-key" });

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
        var provider = ProviderPublishing(rsa.ExportSubjectPublicKeyInfoPem(),
            new VaultTransitOptions { SigningKeyName = "sign-key", EncryptionKeyName = "enc-key" });

        var key = await SingleAsync(provider.GetEncryptionKeys(), TestContext.Current.CancellationToken);

        Assert.Equal("enc-key", key.KeyId);
        Assert.Equal(PublicKeyUsages.Encryption, key.Usage);
        Assert.Equal(EncryptionAlgorithms.KeyManagement.RsaOaep256, key.Algorithm);
        Assert.True(key.HasPublicKey);
        Assert.False(key.HasPrivateKey);
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
