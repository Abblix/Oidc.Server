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
using System.Text;
using System.Text.Json;
using Azure.Core;

namespace Abblix.Oidc.Server.Azure.UnitTests;

/// <summary>
/// Credential that returns a fixed token without any network call, so the Azure SDK's authentication pipeline
/// never reaches Entra ID during a test.
/// </summary>
internal sealed class StaticTokenCredential : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => new("stub-token", DateTimeOffset.MaxValue);

    public override ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext, CancellationToken cancellationToken)
        => ValueTask.FromResult(GetToken(requestContext, cancellationToken));
}

/// <summary>
/// Records the requests the Azure SDK sends through its transport and returns the canned response the responder
/// builds, so <see cref="AzureKeyVaultClient"/> is exercised against Key Vault wire shapes without a live vault.
/// </summary>
internal sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
    : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];
    public HttpRequestMessage? LastRequest => Requests.Count == 0 ? null : Requests[^1];

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        return Task.FromResult(responder(request));
    }

    public static HttpResponseMessage Json(HttpStatusCode status, string json)
        => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
}

/// <summary>Builders for the Key Vault JSON payloads the stub transport returns.</summary>
internal static class AzureResponses
{
    public static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>A public-only RSA key bundle, the shape <c>KeyClient.GetKey</c> and the crypto client's
    /// just-in-time key download expect.</summary>
    public static string KeyBundle(string vaultUri, string keyName, RSAParameters publicKey)
        => JsonSerializer.Serialize(new
        {
            key = new
            {
                kid = $"{vaultUri}keys/{keyName}/v1",
                kty = "RSA",
                key_ops = new[] { "sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey" },
                n = Base64Url(publicKey.Modulus!),
                e = Base64Url(publicKey.Exponent!),
            },
            attributes = new { enabled = true },
        });

    /// <summary>A public-only P-256 EC key bundle, the shape the SDK expects for an EC key.</summary>
    public static string EcKeyBundle(string vaultUri, string keyName, ECParameters publicKey)
        => JsonSerializer.Serialize(new
        {
            key = new
            {
                kid = $"{vaultUri}keys/{keyName}/v1",
                kty = "EC",
                crv = "P-256",
                key_ops = new[] { "sign", "verify" },
                x = Base64Url(publicKey.Q.X!),
                y = Base64Url(publicKey.Q.Y!),
            },
            attributes = new { enabled = true },
        });

    /// <summary>A sign or decrypt result, both shaped <c>{ kid, value }</c> with a base64url value.</summary>
    public static string CryptoResult(string vaultUri, string keyName, byte[] value)
        => JsonSerializer.Serialize(new { kid = $"{vaultUri}keys/{keyName}/v1", value = Base64Url(value) });

    /// <summary>A "get key versions" page: each version's identifier, creation time (Unix seconds) and enabled
    /// flag, the shape <c>KeyClient.GetPropertiesOfKeyVersions</c> pages over.</summary>
    public static string KeyVersionsList(string vaultUri, string keyName, params (string Version, long CreatedUnix)[] versions)
        => JsonSerializer.Serialize(new
        {
            value = versions.Select(version => new
            {
                kid = $"{vaultUri}keys/{keyName}/{version.Version}",
                attributes = new { enabled = true, created = version.CreatedUnix },
            }).ToArray(),
            nextLink = (string?)null,
        });
}
