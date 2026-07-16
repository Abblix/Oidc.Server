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
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Exercises the Transit wire contract of <see cref="VaultTransitClient"/> against a stub transport: the RSA and
/// EC sign request shapes, the <c>vault:v&lt;n&gt;:</c> envelope framing, the 400-to-null decryption semantics,
/// the algorithm gate, and the RSA / EC public-key import.
/// </summary>
public sealed class VaultTransitClientTests : IDisposable
{
    // Each test builds a client over a stub transport. In production IHttpClientFactory owns the HttpClient and
    // VaultTransitClient deliberately does not dispose it (a typed client never owns the factory's handler), so
    // here the test owns that lifetime: track every created HttpClient and dispose them at test-class teardown.
    private readonly List<HttpClient> _httpClients = [];

    private VaultTransitClient ClientOver(StubHttpMessageHandler handler)
    {
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/transit/") };
        _httpClients.Add(httpClient);
        return new VaultTransitClient(httpClient);
    }

    public void Dispose()
    {
        foreach (var httpClient in _httpClients)
            httpClient.Dispose();
    }

    [Fact]
    public async Task SignAsync_Rs256_PostsPkcs1v15Sha256_AndStripsVersionPrefix()
    {
        var signature = new byte[] { 1, 2, 3, 4 };
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { signature = $"vault:v3:{Convert.ToBase64String(signature)}" } }));
        var client = ClientOver(handler);

        var data = "\t\t"u8.ToArray();
        var result = await client.SignAsync("oidc-sign", SigningAlgorithms.RS256, data, TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        var root = body.RootElement;
        Assert.Equal(Convert.ToBase64String(data), root.GetProperty("input").GetString());
        Assert.Equal("pkcs1v15", root.GetProperty("signature_algorithm").GetString());
        Assert.Equal("sha2-256", root.GetProperty("hash_algorithm").GetString());
        Assert.False(root.GetProperty("prehashed").GetBoolean());
    }

    [Fact]
    public async Task SignAsync_Es256_UsesJwsMarshalingSoNoAsn1Conversion()
    {
        var signature = new byte[] { 5, 6, 7, 8 };
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { signature = $"vault:v1:{Convert.ToBase64String(signature)}" } }));
        var client = ClientOver(handler);

        var result = await client.SignAsync("oidc-sign", SigningAlgorithms.ES256, [1], TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        var root = body.RootElement;
        Assert.Equal("jws", root.GetProperty("marshaling_algorithm").GetString());
        Assert.Equal("sha2-256", root.GetProperty("hash_algorithm").GetString());
        Assert.False(root.TryGetProperty("signature_algorithm", out _)); // EC has no signature_algorithm
    }

    [Fact]
    public async Task SignAsync_RejectsUnsupportedAlgorithm_WithoutCallingTransit()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));
        var client = ClientOver(handler);

        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.SignAsync("oidc-sign", "HS256", [1], TestContext.Current.CancellationToken).AsTask());

        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task DecryptAsync_FramesCiphertextAsVaultEnvelope_AndReturnsDecodedPlaintext()
    {
        var plaintext = new byte[] { 7, 7, 7 };
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { plaintext = Convert.ToBase64String(plaintext) } }));
        var client = ClientOver(handler);

        var ciphertext = new byte[] { 5, 5 };
        var result = await client.UnwrapKeyAsync(
            "oidc-enc", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            ciphertext, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        Assert.Equal("vault:v1:" + Convert.ToBase64String(ciphertext),
            body.RootElement.GetProperty("ciphertext").GetString());
    }

    [Fact]
    public async Task DecryptAsync_ReturnsNull_OnBadRequest()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.BadRequest, new { errors = new[] { "decryption failed" } }));
        var client = ClientOver(handler);

        var result = await client.UnwrapKeyAsync(
            "oidc-enc", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [1], TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task DecryptAsync_Throws_OnForbidden()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.Forbidden, new { errors = new[] { "permission denied" } }));
        var client = ClientOver(handler);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.UnwrapKeyAsync(
            "oidc-enc", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [1], TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task DecryptAsync_RejectsUnsupportedAlgorithm_WithoutCallingTransit()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));
        var client = ClientOver(handler);

        await Assert.ThrowsAsync<NotSupportedException>(() => client.UnwrapKeyAsync(
            "oidc-enc", EncryptionAlgorithms.KeyManagement.Rsa1_5, new JsonWebTokenHeader(new JsonObject()),
            [1], TestContext.Current.CancellationToken).AsTask());

        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task GetPublicKeyAsync_ImportsLatestVersion_OfAnRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var expected = rsa.ExportParameters(false);
        var handler = KeyResponse("rsa-2048", rsa.ExportSubjectPublicKeyInfoPem());
        var client = ClientOver(handler);

        var key = await client.GetPublicKeyAsync("oidc-sign", TestContext.Current.CancellationToken);

        var rsaKey = Assert.IsType<RsaJsonWebKey>(key);
        Assert.Equal(expected.Modulus, rsaKey.Modulus);
        Assert.False(rsaKey.HasPrivateKey);
    }

    [Fact]
    public async Task GetPublicKeyAsync_ImportsLatestVersion_OfAnEcKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var handler = KeyResponse("ecdsa-p256", ecdsa.ExportSubjectPublicKeyInfoPem());
        var client = ClientOver(handler);

        var key = await client.GetPublicKeyAsync("oidc-sign", TestContext.Current.CancellationToken);

        var ecKey = Assert.IsType<EllipticCurveJsonWebKey>(key);
        Assert.Equal("P-256", ecKey.Curve);
        Assert.False(ecKey.HasPrivateKey);
    }

    private static StubHttpMessageHandler KeyResponse(string keyType, string publicKeyPem)
        => new((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK,
            new
            {
                data = new
                {
                    type = keyType,
                    latest_version = 1,
                    keys = new Dictionary<string, object> { ["1"] = new { public_key = publicKeyPem } },
                },
            }));
}
