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
using Xunit;

namespace Abblix.Oidc.Server.Azure.UnitTests;

/// <summary>
/// Exercises <see cref="AzureKeyVaultClient"/> against a stub transport and a fake credential, proving the
/// IHttpClientFactory seam drives the Azure SDK end to end: the injected <see cref="HttpMessageHandler"/> is the
/// transport for every Key Vault call, so signing, unwrapping and public-key fetch round-trip without a live vault.
/// </summary>
public class AzureKeyVaultClientTests
{
    private const string VaultUri = "https://contoso.vault.azure.net/";

    private static AzureKeyVaultClient ClientOver(StubHttpMessageHandler handler)
        => new(new AzureKeyVaultOptions { KeyVaultUri = VaultUri }, new StaticTokenCredential(), new HttpClient(handler));

    [Fact]
    public async Task GetPublicKeyAsync_ReadsTheKeyThroughTheInjectedTransport()
    {
        using var rsa = RSA.Create(2048);
        var expected = rsa.ExportParameters(false);
        var handler = new StubHttpMessageHandler(
            _ => StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", expected)));
        var client = ClientOver(handler);

        var result = await client.GetPublicKeyAsync("oidc-sign", TestContext.Current.CancellationToken);

        Assert.Equal(expected.Modulus, result.Modulus);
        Assert.Equal(expected.Exponent, result.Exponent);
        Assert.NotNull(handler.LastRequest); // the SDK went through our injected HttpClient
    }

    [Fact]
    public async Task SignAsync_SignsThroughTheInjectedTransport()
    {
        var signature = new byte[] { 3, 1, 4, 1, 5, 9 };
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportParameters(false);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/sign", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.CryptoResult(VaultUri, "oidc-sign", signature))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-sign", publicKey)));
        var client = ClientOver(handler);

        var result = await client.SignAsync("oidc-sign", new byte[] { 9, 9 }, TestContext.Current.CancellationToken);

        Assert.Equal(signature, result);
    }

    [Fact]
    public async Task DecryptAsync_UnwrapsThroughTheInjectedTransport()
    {
        var plaintext = new byte[] { 2, 7, 1, 8 };
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportParameters(false);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.CryptoResult(VaultUri, "oidc-enc", plaintext))
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-enc", publicKey)));
        var client = ClientOver(handler);

        var result = await client.DecryptAsync("oidc-enc", new byte[] { 5, 5 }, TestContext.Current.CancellationToken);

        Assert.Equal(plaintext, result);
    }

    [Fact]
    public async Task DecryptAsync_ReturnsNull_OnVaultFailure()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportParameters(false);
        var handler = new StubHttpMessageHandler(request =>
            request.RequestUri!.AbsolutePath.EndsWith("/decrypt", StringComparison.Ordinal)
                ? StubHttpMessageHandler.Json(HttpStatusCode.Forbidden, """{"error":{"code":"Forbidden","message":"denied"}}""")
                : StubHttpMessageHandler.Json(HttpStatusCode.OK, AzureResponses.KeyBundle(VaultUri, "oidc-enc", publicKey)));
        var client = ClientOver(handler);

        var result = await client.DecryptAsync("oidc-enc", new byte[] { 5, 5 }, TestContext.Current.CancellationToken);

        Assert.Null(result);
    }
}
