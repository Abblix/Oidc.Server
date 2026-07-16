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
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Verifies the algorithm gate of <see cref="VaultCustodian"/>: the RSA operations forward to Transit, while an
/// unsupported algorithm is rejected before any network round-trip, and ECDH-ES agreement is unreachable.
/// </summary>
public class VaultCustodianTests
{
    private static (VaultCustodian Custodian, StubHttpMessageHandler Handler) Build(
        Func<HttpRequestMessage, string, HttpResponseMessage> responder)
    {
        var handler = new StubHttpMessageHandler(responder);
        var client = new VaultTransitClient(new HttpClient(handler)
        {
            BaseAddress = new Uri("http://vault.test/v1/transit/"),
        });
        return (new VaultCustodian(client), handler);
    }

    [Fact]
    public async Task SignAsync_ForwardsRs256_ToTransit()
    {
        var signature = new byte[] { 8, 8, 8 };
        var (custodian, _) = Build((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { signature = $"vault:v1:{Convert.ToBase64String(signature)}" } }));

        var result = await custodian.SignAsync(
            "oidc-sign", SigningAlgorithms.RS256, new byte[] { 1 }, TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
    }

    [Fact]
    public async Task SignAsync_RejectsNonRs256_WithoutCallingTransit()
    {
        var (custodian, handler) = Build((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));

        await Assert.ThrowsAsync<NotSupportedException>(() => custodian
            .SignAsync("oidc-sign", "ES256", new byte[] { 1 }, TestContext.Current.CancellationToken).AsTask());

        Assert.Null(handler.LastRequest); // the guard fires before any network round-trip
    }

    [Fact]
    public async Task UnwrapKeyAsync_ForwardsRsaOaep256_ToTransit()
    {
        var plaintext = new byte[] { 4, 5, 6 };
        var (custodian, _) = Build((_, _) => StubHttpMessageHandler.Json(
            HttpStatusCode.OK, new { data = new { plaintext = Convert.ToBase64String(plaintext) } }));

        var result = await custodian.UnwrapKeyAsync(
            "oidc-enc", EncryptionAlgorithms.KeyManagement.RsaOaep256,
            new JsonWebTokenHeader(new JsonObject()), new byte[] { 1 }, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task UnwrapKeyAsync_RejectsNonRsaOaep256_WithoutCallingTransit()
    {
        var (custodian, handler) = Build((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));

        await Assert.ThrowsAsync<NotSupportedException>(() => custodian.UnwrapKeyAsync(
            "oidc-enc", "RSA1_5", new JsonWebTokenHeader(new JsonObject()),
            new byte[] { 1 }, TestContext.Current.CancellationToken).AsTask());

        Assert.Null(handler.LastRequest);
    }

    [Fact]
    public void AgreeKeyAsync_IsNotSupported()
    {
        var (custodian, _) = Build((_, _) => StubHttpMessageHandler.Json(HttpStatusCode.OK, new { }));

        Assert.Throws<NotSupportedException>(() => _ = custodian.AgreeKeyAsync(
            "oidc-enc", "ECDH-ES", new RsaJsonWebKey(), TestContext.Current.CancellationToken));
    }
}
