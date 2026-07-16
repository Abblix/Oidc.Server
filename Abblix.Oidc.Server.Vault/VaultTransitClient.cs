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

using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// Thin HTTP client over the Vault / OpenBao Transit secrets engine. Every private-key operation is a network
/// round-trip: the key is created inside Transit as non-exportable, so its private half never leaves the engine
/// and this client only moves bytes across the boundary. The typed <see cref="HttpClient"/> is configured by
/// <c>AddVaultExternalKeys</c> with the Transit base address (<c>{Address}/v1/{mount}/</c>) and the auth header.
/// </summary>
public sealed class VaultTransitClient(HttpClient http)
{
    /// <summary>
    /// Signs the JWS signing input with a Transit RSA key. RS256 maps to PKCS#1 v1.5 over SHA-256, and Transit
    /// hashes the input itself (<c>prehashed: false</c>) with no size limit. Returns the raw JWS signature bytes
    /// after stripping Transit's <c>vault:v&lt;n&gt;:</c> version prefix.
    /// </summary>
    public async Task<byte[]> SignAsync(string keyName, byte[] data, CancellationToken cancellationToken)
    {
        var request = new
        {
            input = Convert.ToBase64String(data),
            signature_algorithm = "pkcs1v15",
            hash_algorithm = "sha2-256",
            prehashed = false,
        };

        using var document = await SendAsync(HttpMethod.Post, $"sign/{keyName}", request, cancellationToken);
        var signature = document.RootElement.GetProperty("data").GetProperty("signature").GetString()!;

        // Transit returns "vault:v<version>:<base64(signature)>"; the wire signature is the last segment.
        return Convert.FromBase64String(signature[(signature.LastIndexOf(':') + 1)..]);
    }

    /// <summary>
    /// Unwraps (decrypts) an RSA-OAEP-256 Content Encryption Key with a Transit RSA key. A standard JWE
    /// ciphertext is addressed by framing it as <c>vault:v1:&lt;base64&gt;</c>. Returns null on a decryption
    /// failure (HTTP 400) so a wrong key or tampered ciphertext is indistinguishable, which the seam's
    /// padding-oracle mitigation depends on; a 403/5xx (bad token, sealed Vault) still throws.
    /// </summary>
    public async Task<byte[]?> DecryptAsync(string keyName, byte[] ciphertext, CancellationToken cancellationToken)
    {
        // A key that never rotates has only version v1. A rotating production custodian records which version
        // wrapped each CEK and frames the prefix with that version instead of a constant.
        var request = new { ciphertext = "vault:v1:" + Convert.ToBase64String(ciphertext) };

        var (status, document) = await TrySendAsync(HttpMethod.Post, $"decrypt/{keyName}", request, cancellationToken);
        using (document)
        {
            if (status == HttpStatusCode.BadRequest)
                return null;

            EnsureSuccess(status, document, $"decrypt/{keyName}");
            var plaintext = document!.RootElement.GetProperty("data").GetProperty("plaintext").GetString()!;
            return Convert.FromBase64String(plaintext);
        }
    }

    /// <summary>
    /// Fetches the public half of a Transit key as a PEM (SubjectPublicKeyInfo). Called once per key at startup:
    /// the public key is a durable artifact captured at generation, so JWKS publishing and signature
    /// verification run locally against it and never touch this client on the hot path.
    /// </summary>
    public async Task<string> GetPublicKeyPemAsync(string keyName, CancellationToken cancellationToken)
    {
        using var document = await SendAsync(HttpMethod.Get, $"keys/{keyName}", body: null, cancellationToken);
        var data = document.RootElement.GetProperty("data");
        var latestVersion = data.GetProperty("latest_version").GetInt32().ToString(CultureInfo.InvariantCulture);
        return data.GetProperty("keys").GetProperty(latestVersion).GetProperty("public_key").GetString()!;
    }

    private async Task<JsonDocument> SendAsync(HttpMethod method, string path, object? body, CancellationToken cancellationToken)
    {
        var (status, document) = await TrySendAsync(method, path, body, cancellationToken);
        EnsureSuccess(status, document, path);
        return document!;
    }

    private async Task<(HttpStatusCode Status, JsonDocument? Document)> TrySendAsync(
        HttpMethod method, string path, object? body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = JsonContent.Create(body);

        using var response = await http.SendAsync(request, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        var document = string.IsNullOrEmpty(payload) ? null : JsonDocument.Parse(payload);
        return (response.StatusCode, document);
    }

    private static void EnsureSuccess(HttpStatusCode status, JsonDocument? document, string path)
    {
        if ((int)status is >= 200 and < 300)
            return;

        var errors = document?.RootElement.TryGetProperty("errors", out var e) == true ? e.ToString() : "(none)";
        throw new InvalidOperationException($"Vault Transit '{path}' failed with {(int)status}: {errors}");
    }
}
