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
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Xunit;

namespace Abblix.Oidc.Server.Azure.UnitTests;

/// <summary>
/// Exercises <see cref="AzureKeyVaultClient"/> against a stub transport and a fake credential, proving the
/// IHttpClientFactory seam drives the Azure SDK end to end: the injected <see cref="HttpMessageHandler"/> is the
/// transport for every Key Vault call, so RSA and EC signing, unwrapping and public-key fetch round-trip without a
/// live vault.
/// </summary>
public class AzureKeyVaultClientTests
{
    private const string VaultUri = "https://contoso.vault.azure.net/";

    private static AzureKeyVaultClient ClientOver(StubHttpMessageHandler handler)
        => new(new AzureKeyVaultOptions { KeyVaultUri = VaultUri }, new StaticTokenCredential(), new HttpClient(handler));

    private static async Task<JsonWebKey> FirstPublicKeyAsync(IAsyncEnumerable<KeyVersion> versions)
    {
        await using var enumerator = versions.GetAsyncEnumerator();
        if (!await enumerator.MoveNextAsync())
            throw new InvalidOperationException("The custodian returned no key versions.");
        return enumerator.Current.PublicKey;
    }

    [Fact]
    public async Task GetKeyVersionsAsync_ImportsAnRsaKeyThroughTheInjectedTransport()
    {
        using var rsa = RSA.Create(2048);
        var expected = rsa.ExportParameters(false);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(VaultUri, "oidc-sign", ("v1", 1_700_000_000L)))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", expected)));

        var key = await FirstPublicKeyAsync(ClientOver(handler).GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken));

        var rsaKey = Assert.IsType<RsaJsonWebKey>(key);
        Assert.Equal(expected.Modulus, rsaKey.Modulus);
        Assert.False(rsaKey.HasPrivateKey);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_ImportsAnEcKeyThroughTheInjectedTransport()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(VaultUri, "oidc-sign", ("v1", 1_700_000_000L)))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.EcKeyBundle(VaultUri, "oidc-sign", ecdsa.ExportParameters(false))));

        var key = await FirstPublicKeyAsync(ClientOver(handler).GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken));

        var ecKey = Assert.IsType<EllipticCurveJsonWebKey>(key);
        Assert.Equal("P-256", ecKey.Curve);
        Assert.False(ecKey.HasPrivateKey);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_PublishesEveryEnabledVersion_WithVersionedKidsAndCreationTimes()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var created1 = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000L);
        var created2 = DateTimeOffset.FromUnixTimeSeconds(1_710_000_000L);

        var handler = new StubHttpMessageHandler(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/versions", StringComparison.Ordinal))
                return StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyVersionsList(
                    VaultUri, "oidc-sign", ("v1", created1.ToUnixTimeSeconds()), ("v2", created2.ToUnixTimeSeconds())));

            // A per-version key fetch: the crypto material of the version the path names. The bundle's own kid is
            // ignored - the client stamps the kid from the key name and version.
            var parameters = path.EndsWith("/v1", StringComparison.Ordinal)
                ? rsa1.ExportParameters(false)
                : rsa2.ExportParameters(false);
            return StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", parameters));
        });

        var versions = new List<KeyVersion>();
        await foreach (var version in ClientOver(handler).GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken))
            versions.Add(version);

        Assert.Equal(2, versions.Count);
        var first = versions.Single(version => version.PublicKey.KeyId == "oidc-sign/v1");
        var second = versions.Single(version => version.PublicKey.KeyId == "oidc-sign/v2");
        Assert.Equal(created1, first.CreatedAt);
        Assert.Equal(created2, second.CreatedAt);
        Assert.Equal(rsa1.ExportParameters(false).Modulus, Assert.IsType<RsaJsonWebKey>(first.PublicKey).Modulus);
    }

    [Fact]
    public async Task SignAsync_Rs256_SignsThroughTheInjectedTransport()
    {
        var signature = new byte[] { 3, 1, 4, 1, 5, 9 };
        using var rsa = RSA.Create(2048);
        var handler = SignResponder("oidc-sign", signature, AzureResponses.KeyBundle(VaultUri, "oidc-sign", rsa.ExportParameters(false)));

        var result = await ClientOver(handler).SignAsync(
            "oidc-sign", SigningAlgorithms.RS256, [9, 9], TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
    }

    [Fact]
    public async Task SignAsync_Es256_SignsThroughTheInjectedTransport()
    {
        var signature = new byte[] { 2, 7, 1, 8, 2, 8 };
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var handler = SignResponder("oidc-sign", signature, AzureResponses.EcKeyBundle(VaultUri, "oidc-sign", ecdsa.ExportParameters(false)));

        var result = await ClientOver(handler).SignAsync(
            "oidc-sign", SigningAlgorithms.ES256, [9, 9], TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
    }

    [Fact]
    public async Task SignAsync_RejectsUnsupportedAlgorithm()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK));

        await Assert.ThrowsAsync<NotSupportedException>(() => ClientOver(handler)
            .SignAsync("oidc-sign", "HS256", [1], TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task DecryptAsync_RsaOaep256_UnwrapsThroughTheInjectedTransport()
    {
        var plaintext = new byte[] { 2, 7, 1, 8 };
        using var rsa = RSA.Create(2048);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.CryptoResult(VaultUri, "oidc-enc", plaintext))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-enc", rsa.ExportParameters(false))));

        var result = await ClientOver(handler).UnwrapKeyAsync(
            "oidc-enc", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [5, 5], TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task DecryptAsync_ReturnsNull_OnVaultFailure()
    {
        using var rsa = RSA.Create(2048);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.Forbidden, """{"error":{"code":"Forbidden","message":"denied"}}""")
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-enc", rsa.ExportParameters(false))));

        var result = await ClientOver(handler).UnwrapKeyAsync(
            "oidc-enc", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [5, 5], TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    // The crypto client may fetch the key (a JIT GET) before the remote sign; return the key bundle for the GET and
    // the signature for the POST to /sign.
    private static StubHttpMessageHandler SignResponder(string keyName, byte[] signature, string keyBundle)
        => new(request => request.RequestUri!.AbsolutePath.EndsWith("/sign", StringComparison.Ordinal)
            ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.CryptoResult(VaultUri, keyName, signature))
            : StubHttpMessageHandler.Json(HttpStatusCode.OK, keyBundle));
}
