// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Runtime.CompilerServices;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Holds the provider's keys in the Vault / OpenBao Transit secrets engine. Every private-key operation is a
/// network round-trip: the key is created inside Transit as non-exportable, so its private half never leaves the
/// engine and this custodian only moves bytes across the boundary.
/// </summary>
/// <remarks>
/// What Transit can do decides what this custodian supports: it signs and it unwraps RSA-OAEP, and it exposes no
/// key-agreement primitive, so ECDH-ES is out. That is a property of the engine, which is why the engine is in
/// the name.
/// </remarks>
internal sealed partial class TransitCustodian(
    ILogger<TransitCustodian> logger,
    IHttpClientFactory httpClientFactory,
    IOptions<VaultTransitOptions> options)
    : IKeyCustodian
{
    /// <summary>
    /// The shared client, held for this singleton's lifetime. Resolved by name rather than injected, because the
    /// factory's own clients are transient and the key ring shares this one.
    /// </summary>
    private readonly HttpClient _httpClient = httpClientFactory.CreateClient(VaultTransport.HttpClientName);

    /// <summary>
    /// The Transit mount, spelled into every path. The client stops at <c>/v1/</c> because it is shared with the
    /// key ring, which lives on a different mount.
    /// </summary>
    private string Mount => options.Value.TransitMount;

    /// <summary>
    /// Signs the JWS signing input with a Transit key under the given JWS algorithm. RSA maps to PKCS#1 v1.5
    /// (<c>RS*</c>) or PSS (<c>PS*</c>); EC (<c>ES*</c>) uses Transit's <c>jws</c> marshaling so the signature is
    /// R||S already, with no ASN.1 conversion. Transit hashes the input itself (<c>prehashed: false</c>). Returns
    /// the raw JWS signature bytes after stripping Transit's <c>vault:v&lt;n&gt;:</c> version prefix.
    /// </summary>
    public async Task<byte[]> SignAsync(
        string keyId,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        var (name, version) = TransitKeyId.Parse(keyId);
        var request = TransitSignRequests.For(algorithm, Convert.ToBase64String(data), version);
        var path = $"{Mount}/sign/{name}";

        using var response = await SendGuardedAsync(HttpMethod.Post, path, request, cancellationToken);
        EnsureAnswered(response, path);

        var signature = response.Body(path).RootElement.GetProperty("data").GetProperty("signature").GetString()!;

        // Transit returns "vault:v<version>:<base64(signature)>"; the wire signature is the last segment.
        return Convert.FromBase64String(signature[(signature.LastIndexOf(':') + 1)..]);
    }

    /// <summary>
    /// Unwraps (decrypts) an RSA-OAEP-256 Content Encryption Key with a Transit RSA key (the only key-management
    /// algorithm Transit's RSA decrypt provisions). Transit reads the key version from the ciphertext framing, so
    /// the standard JWE ciphertext is framed as <c>vault:v&lt;version&gt;:&lt;base64&gt;</c> with the version the
    /// <c>kid</c> names, addressing the exact version that wrapped the CEK. Returns null on a decryption failure
    /// (HTTP 400) so a wrong key or tampered ciphertext is indistinguishable, which the seam's padding-oracle
    /// mitigation depends on; a 403/5xx (bad token, sealed Vault) still throws. The JWE header is unused: RSA-OAEP
    /// unwrap needs only the ciphertext.
    /// </summary>
    public async Task<byte[]?> UnwrapKeyAsync(
        string keyId,
        string algorithm,
        JsonWebTokenHeader header,
        byte[] encryptedKey,
        CancellationToken cancellationToken)
    {
        if (algorithm != EncryptionAlgorithms.KeyManagement.RsaOaep256)
            throw new NotSupportedException(
                $"The Vault Transit store unwraps {EncryptionAlgorithms.KeyManagement.RsaOaep256} only; got '{algorithm}'.");

        var (name, version) = TransitKeyId.Parse(keyId);
        var request = new { ciphertext = $"vault:v{version}:{Convert.ToBase64String(encryptedKey)}" };
        var path = $"{Mount}/decrypt/{name}";

        using var response = await SendGuardedAsync(HttpMethod.Post, path, request, cancellationToken);
        if (response.Status == HttpStatusCode.BadRequest)
        {
            LogUnwrapRejected(keyId);
            return null;
        }

        EnsureAnswered(response, path);
        var plaintext = response.Body(path).RootElement.GetProperty("data").GetProperty("plaintext").GetString()!;
        return Convert.FromBase64String(plaintext);
    }

    /// <summary>
    /// Derives the ECDH-ES shared secret. Vault Transit exposes no key-agreement primitive, so this store does not
    /// support ECDH-ES; a store built on AWS KMS (DeriveSharedSecret) or a PKCS#11 HSM (CKM_ECDH1_DERIVE) can.
    /// </summary>
    public Task<byte[]> AgreeKeyAsync(
        string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
        => throw new NotSupportedException(
            "Vault Transit exposes no ECDH key-agreement primitive; ECDH-ES is not supported by this store.");

    /// <summary>
    /// Enumerates every version of the Transit key as a public-only JWK (RSA or EC, per the Transit key type).
    /// Called at publication time, so JWKS publishing and signature verification run locally against the result
    /// and never touch this client on the hot path.
    /// </summary>
    public async IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
        string keyName,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var path = $"{Mount}/keys/{keyName}";
        using var response = await SendGuardedAsync(HttpMethod.Get, path, body: null, cancellationToken);
        EnsureAnswered(response, path);

        foreach (var version in TransitKeyVersions.Read(response.Body(path).RootElement.GetProperty("data"), keyName))
            yield return version;
    }

    /// <summary>
    /// Turns a failed answer into the exception the endpoints read, logging it here rather than at the endpoint:
    /// this is the last place that still knows which custodian, which path, and whether the answer was an outage
    /// or a refusal. A status some caller reads as an answer never arrives here.
    /// </summary>
    private void EnsureAnswered(ApiResponse response, string path)
    {
        if (response.IsSuccess)
            return;

        var failure = response.Failure(path);
        LogCustodianFailed(path, VaultFailure.IsTransient(response.Status), failure);
        throw failure;
    }

    /// <summary>
    /// Sends a request to Vault, reporting a failure that never reached it as the custodian being temporarily
    /// unable. Without this the transport exception escapes to an endpoint that cannot read it, and the caller
    /// is told nothing it can act on. The status answers are classified separately, by
    /// <see cref="ApiResponse.Failure"/>.
    /// </summary>
    private async Task<ApiResponse> SendGuardedAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        try
        {
            return await _httpClient.SendAsync(method, path, body, cancellationToken);
        }
        catch (KeyCustodianUnavailableException unreachable)
        {
            // The transport classified it; this adds the line an operator reads, which the transport cannot
            // write because it holds no logger and serves the key ring as well.
            LogCustodianFailed(path, temporary: true, unreachable);
            throw;
        }
    }
}
