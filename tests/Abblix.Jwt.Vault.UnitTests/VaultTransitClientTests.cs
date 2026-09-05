// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Exercises the Transit wire contract of <see cref="TransitCustodian"/> against a stub transport: the RSA and
/// EC sign request shapes, the <c>vault:v&lt;n&gt;:</c> envelope framing, the 400-to-null decryption semantics,
/// the algorithm gate, and the RSA / EC public-key import.
/// </summary>
public sealed class VaultTransitClientTests : IDisposable
{
    // Each test builds a custodian over a stub transport. In production IHttpClientFactory owns the HttpClient and
    // nothing here disposes it (a client from the factory never owns the factory's handler), so the test owns that
    // lifetime instead: track every created HttpClient and dispose them at test-class teardown.
    private readonly List<HttpClient> _httpClients = [];

    private TransitCustodian ClientOver(StubHttpMessageHandler handler)
    {
        // The address stops at the server root, as the shared transport's does: the mount is the custodian's to
        // spell into every path, because the key ring rides this same client on a different one.
        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _httpClients.Add(httpClient);

        return new TransitCustodian(
            NullLogger<TransitCustodian>.Instance,
            new StubHttpClientFactory(httpClient),
            Options.Create(new VaultTransitOptions { TransitMount = "transit" }));
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
        var result = await client.SignAsync("oidc-sign:2", SigningAlgorithms.RS256, data, TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);

        // The mount is spelled into the path, not baked into the address: the transport is shared with the key
        // ring, which lives on a different mount of the same server.
        Assert.Equal("https://vault.test/v1/transit/sign/oidc-sign", handler.LastRequest!.RequestUri!.ToString());

        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        var root = body.RootElement;
        Assert.Equal(Convert.ToBase64String(data), root.GetProperty("input").GetString());
        Assert.Equal("pkcs1v15", root.GetProperty("signature_algorithm").GetString());
        Assert.Equal("sha2-256", root.GetProperty("hash_algorithm").GetString());
        Assert.False(root.GetProperty("prehashed").GetBoolean());
        Assert.Equal(2, root.GetProperty("key_version").GetInt32()); // the version the kid pins
    }

    [Fact]
    public async Task SignAsync_Es256_UsesJwsMarshalingSoNoAsn1Conversion()
    {
        var signature = new byte[] { 5, 6, 7, 8 };
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { signature = $"vault:v1:{Convert.ToBase64String(signature)}" } }));
        var client = ClientOver(handler);

        var result = await client.SignAsync("oidc-sign:4", SigningAlgorithms.ES256, [1], TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        var root = body.RootElement;
        Assert.Equal("jws", root.GetProperty("marshaling_algorithm").GetString());
        Assert.Equal("sha2-256", root.GetProperty("hash_algorithm").GetString());
        Assert.Equal(4, root.GetProperty("key_version").GetInt32());
        Assert.False(root.TryGetProperty("signature_algorithm", out _)); // EC has no signature_algorithm
    }

    [Theory]
    [InlineData(SigningAlgorithms.RS256, "pkcs1v15", "sha2-256")]
    [InlineData(SigningAlgorithms.RS384, "pkcs1v15", "sha2-384")]
    [InlineData(SigningAlgorithms.RS512, "pkcs1v15", "sha2-512")]
    [InlineData(SigningAlgorithms.PS256, "pss", "sha2-256")]
    [InlineData(SigningAlgorithms.PS384, "pss", "sha2-384")]
    [InlineData(SigningAlgorithms.PS512, "pss", "sha2-512")]
    public async Task SignAsync_SendsTheTransitNameOfEveryRsaAlgorithmItAccepts(
        string algorithm, string expectedSignatureAlgorithm, string expectedHashAlgorithm)
    {
        // A hand-written mapping table invites transposition, and a transposed arm here is not a crash: Vault
        // signs happily with whatever it was told, so the token goes out signed under one algorithm while its JWS
        // header advertises another. Nothing local notices - the failure lands on whoever verifies it.
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { signature = "vault:v1:AQID" } }));

        await ClientOver(handler).SignAsync("oidc-sign:1", algorithm, [1], TestContext.Current.CancellationToken);

        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        var root = body.RootElement;
        Assert.Equal(expectedSignatureAlgorithm, root.GetProperty("signature_algorithm").GetString());
        Assert.Equal(expectedHashAlgorithm, root.GetProperty("hash_algorithm").GetString());
    }

    [Theory]
    [InlineData(SigningAlgorithms.ES256, "sha2-256")]
    [InlineData(SigningAlgorithms.ES384, "sha2-384")]
    [InlineData(SigningAlgorithms.ES512, "sha2-512")]
    public async Task SignAsync_SendsTheTransitHashOfEveryEcAlgorithmItAccepts(
        string algorithm, string expectedHashAlgorithm)
    {
        // Same exposure on the EC side, where the algorithm is carried by the hash alone.
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { signature = "vault:v1:AQID" } }));

        await ClientOver(handler).SignAsync("oidc-sign:1", algorithm, [1], TestContext.Current.CancellationToken);

        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        var root = body.RootElement;
        Assert.Equal(expectedHashAlgorithm, root.GetProperty("hash_algorithm").GetString());
        Assert.Equal("jws", root.GetProperty("marshaling_algorithm").GetString());
    }

    [Fact]
    public async Task SignAsync_RejectsUnsupportedAlgorithm_WithoutCallingTransit()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));
        var client = ClientOver(handler);

        await Assert.ThrowsAsync<NotSupportedException>(
            () => client.SignAsync("oidc-sign:1", "HS256", [1], TestContext.Current.CancellationToken));

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
            "oidc-enc:3", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            ciphertext, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        Assert.Equal("vault:v3:" + Convert.ToBase64String(ciphertext), // the kid's version frames the ciphertext
            body.RootElement.GetProperty("ciphertext").GetString());
    }

    [Fact]
    public async Task DecryptAsync_ReturnsNull_OnBadRequest()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.BadRequest, new { errors = new[] { "decryption failed" } }));
        var client = ClientOver(handler);

        var result = await client.UnwrapKeyAsync(
            "oidc-enc:1", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
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
            "oidc-enc:1", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [1], TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task DecryptAsync_Throws_WhenTheFailureIsOurs(HttpStatusCode status)
    {
        // Only a rejected ciphertext may become null, because null is how the seam says "this did not decrypt" and
        // that is what keeps a wrong key indistinguishable from bad padding. A throttled, sealed or broken Vault is
        // not a decryption failure. Reporting one as null would reject every encrypted token for as long as the
        // fault lasts, silently, and blame the clients for a JWE that is perfectly good.
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            status, new { errors = new[] { "not a decryption failure" } }));

        await Assert.ThrowsAsync<InvalidOperationException>(() => ClientOver(handler).UnwrapKeyAsync(
            "oidc-enc:1", EncryptionAlgorithms.KeyManagement.RsaOaep256, new JsonWebTokenHeader(new JsonObject()),
            [1], TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetKeyVersionsAsync_RefusesAKeyTypeItCannotPublish()
    {
        // Transit will happily hold an ed25519 or a symmetric key, and an operator can point this store at one by
        // configuring a key name. Publishing it is impossible, so the refusal has to name the type - otherwise the
        // failure surfaces as an import error from deep inside the crypto stack, far from the configuration that
        // caused it.
        using var rsa = RSA.Create(2048);
        var handler = KeyResponse("ed25519", rsa.ExportSubjectPublicKeyInfoPem());

        var exception = await Assert.ThrowsAsync<NotSupportedException>(async () =>
        {
            await foreach (var _ in ClientOver(handler).GetKeyVersionsAsync(
                               "oidc-sign", TestContext.Current.CancellationToken))
            {
                // Enumerating is the act under test; the refusal arrives before any version is produced.
            }
        });

        Assert.Contains("ed25519", exception.Message);
    }

    /// <summary>
    /// The store refuses ECDH-ES rather than pretending: Transit exposes no key-agreement primitive, so a
    /// silent fallback would derive a shared secret that is not the one the peer derived, and the failure
    /// would surface as an undecryptable token far from its cause.
    /// </summary>
    [Fact]
    public async Task AgreeKeyAsync_IsRefused_BecauseTransitHasNoAgreementPrimitive()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));

        await Assert.ThrowsAsync<NotSupportedException>(() => ClientOver(handler).AgreeKeyAsync(
            "oidc-enc:1", EncryptionAlgorithms.KeyManagement.EcdhEs, new EllipticCurveJsonWebKey(),
            TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task DecryptAsync_RejectsUnsupportedAlgorithm_WithoutCallingTransit()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));
        var client = ClientOver(handler);

        await Assert.ThrowsAsync<NotSupportedException>(() => client.UnwrapKeyAsync(
            "oidc-enc:1", EncryptionAlgorithms.KeyManagement.Rsa1_5, new JsonWebTokenHeader(new JsonObject()),
            [1], TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_ImportsLatestVersion_OfAnRsaKey()
    {
        using var rsa = RSA.Create(2048);
        var expected = rsa.ExportParameters(false);
        var handler = KeyResponse("rsa-2048", rsa.ExportSubjectPublicKeyInfoPem());
        var client = ClientOver(handler);

        var key = await FirstPublicKeyAsync(client.GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken));

        var rsaKey = Assert.IsType<RsaJsonWebKey>(key);
        Assert.Equal(expected.Modulus, rsaKey.Modulus);
        Assert.False(rsaKey.HasPrivateKey);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_ImportsLatestVersion_OfAnEcKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var handler = KeyResponse("ecdsa-p256", ecdsa.ExportSubjectPublicKeyInfoPem());
        var client = ClientOver(handler);

        var key = await FirstPublicKeyAsync(client.GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken));

        var ecKey = Assert.IsType<EllipticCurveJsonWebKey>(key);
        Assert.Equal("P-256", ecKey.Curve);
        Assert.False(ecKey.HasPrivateKey);
    }

    [Fact]
    public async Task GetKeyVersionsAsync_PublishesEveryVersion_WithVersionedKidsAndCreationTimes()
    {
        using var rsa1 = RSA.Create(2048);
        using var rsa2 = RSA.Create(2048);
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK,
            new
            {
                data = new
                {
                    type = "rsa-2048",
                    latest_version = 2,
                    keys = new Dictionary<string, object>
                    {
                        ["1"] = new { public_key = rsa1.ExportSubjectPublicKeyInfoPem(), creation_time = "2026-01-01T00:00:00Z" },
                        ["2"] = new { public_key = rsa2.ExportSubjectPublicKeyInfoPem(), creation_time = "2026-02-01T00:00:00Z" },
                    },
                },
            }));
        var client = ClientOver(handler);

        var versions = new List<KeyVersion>();
        await foreach (var version in client.GetKeyVersionsAsync("oidc-sign", TestContext.Current.CancellationToken))
            versions.Add(version);

        Assert.Equal(2, versions.Count);
        var first = versions.Single(version => version.PublicKey.KeyId == "oidc-sign:1");
        var second = versions.Single(version => version.PublicKey.KeyId == "oidc-sign:2");
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), first.CreatedAt);
        Assert.Equal(new DateTimeOffset(2026, 2, 1, 0, 0, 0, TimeSpan.Zero), second.CreatedAt);
        Assert.All(versions, version => Assert.IsType<RsaJsonWebKey>(version.PublicKey));
    }

    [Fact]
    public async Task SignAsync_RejectsKeyIdWithoutVersion()
    {
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));
        var client = ClientOver(handler);

        // A kid without the ":<version>" the enumeration stamps cannot address a Transit version, so it fails loud.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.SignAsync("oidc-sign", SigningAlgorithms.RS256, [1], TestContext.Current.CancellationToken));

        Assert.Null(handler.LastRequest);
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
                    keys = new Dictionary<string, object>
                    {
                        ["1"] = new { public_key = publicKeyPem, creation_time = "2026-01-01T00:00:00Z" },
                    },
                },
            }));

    private static async Task<JsonWebKey> FirstPublicKeyAsync(IAsyncEnumerable<KeyVersion> versions)
    {
        await using var enumerator = versions.GetAsyncEnumerator();
        if (!await enumerator.MoveNextAsync())
            throw new InvalidOperationException("The custodian returned no key versions.");
        return enumerator.Current.PublicKey;
    }
}
