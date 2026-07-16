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
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Exercises the Transit wire contract of <see cref="VaultTransitClient"/> against a stub transport: request
/// shapes, the <c>vault:v&lt;n&gt;:</c> envelope framing, and the 400-to-null decryption semantics.
/// </summary>
public class VaultTransitClientTests
{
    private static VaultTransitClient ClientOver(StubHttpMessageHandler handler)
        => new(new HttpClient(handler) { BaseAddress = new Uri("http://vault.test/v1/transit/") });

    [Fact]
    public async Task SignAsync_PostsPkcs1v15Sha256_AndStripsVersionPrefix()
    {
        var signature = new byte[] { 1, 2, 3, 4 };
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { signature = $"vault:v3:{Convert.ToBase64String(signature)}" } }));
        var client = ClientOver(handler);

        var data = new byte[] { 9, 9 };
        var result = await client.SignAsync("oidc-sign", data, TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
        Assert.Equal("http://vault.test/v1/transit/sign/oidc-sign", handler.LastRequest!.RequestUri!.ToString());

        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        var root = body.RootElement;
        Assert.Equal(Convert.ToBase64String(data), root.GetProperty("input").GetString());
        Assert.Equal("pkcs1v15", root.GetProperty("signature_algorithm").GetString());
        Assert.Equal("sha2-256", root.GetProperty("hash_algorithm").GetString());
        Assert.False(root.GetProperty("prehashed").GetBoolean());
    }

    [Fact]
    public async Task DecryptAsync_FramesCiphertextAsVaultEnvelope_AndReturnsDecodedPlaintext()
    {
        var plaintext = new byte[] { 7, 7, 7 };
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { plaintext = Convert.ToBase64String(plaintext) } }));
        var client = ClientOver(handler);

        var ciphertext = new byte[] { 5, 5 };
        var result = await client.DecryptAsync("oidc-enc", ciphertext, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
        Assert.Equal("http://vault.test/v1/transit/decrypt/oidc-enc", handler.LastRequest!.RequestUri!.ToString());

        using var body = JsonDocument.Parse(handler.LastRequestBody!);
        Assert.Equal("vault:v1:" + Convert.ToBase64String(ciphertext),
            body.RootElement.GetProperty("ciphertext").GetString());
    }

    [Fact]
    public async Task DecryptAsync_ReturnsNull_OnBadRequest()
    {
        // A 400 means a wrong key or tampered ciphertext; the client returns null so the two are indistinguishable,
        // which the seam's padding-oracle mitigation depends on.
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.BadRequest, new { errors = new[] { "decryption failed" } }));
        var client = ClientOver(handler);

        var result = await client.DecryptAsync("oidc-enc", new byte[] { 1 }, TestContext.Current.CancellationToken);

        Assert.Null(result);
    }

    [Fact]
    public async Task DecryptAsync_Throws_OnForbidden()
    {
        // A 403 (bad token, sealed Vault) is an operational failure, not a ciphertext-dependent one, so it surfaces.
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.Forbidden, new { errors = new[] { "permission denied" } }));
        var client = ClientOver(handler);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.DecryptAsync("oidc-enc", new byte[] { 1 }, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task GetPublicKeyPemAsync_ReturnsLatestVersionPublicKey()
    {
        using var rsa = RSA.Create(2048);
        var pem = rsa.ExportSubjectPublicKeyInfoPem();
        var handler = new StubHttpMessageHandler((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK,
            new
            {
                data = new
                {
                    latest_version = 2,
                    keys = new Dictionary<string, object>
                    {
                        ["1"] = new { public_key = "-----BEGIN PUBLIC KEY-----\nstale\n-----END PUBLIC KEY-----" },
                        ["2"] = new { public_key = pem },
                    },
                },
            }));
        var client = ClientOver(handler);

        var result = await client.GetPublicKeyPemAsync("oidc-sign", TestContext.Current.CancellationToken);

        Assert.Equal(pem, result);
        Assert.Equal("http://vault.test/v1/transit/keys/oidc-sign", handler.LastRequest!.RequestUri!.ToString());
    }
}
