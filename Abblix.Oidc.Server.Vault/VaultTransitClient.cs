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
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// Thin HTTP client over the Vault / OpenBao Transit secrets engine. Every private-key operation is a network
/// round-trip: the key is created inside Transit as non-exportable, so its private half never leaves the engine
/// and this client only moves bytes across the boundary. The typed <see cref="HttpClient"/> is configured by
/// <c>AddVaultCustodian</c> with the Transit base address (<c>{Address}/v1/{mount}/</c>) and the auth header.
/// </summary>
public sealed class VaultTransitClient(HttpClient httpClient) : IKeyCustodian
{
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
        var (name, version) = ParseKeyId(keyId);
        var request = BuildSignRequest(Convert.ToBase64String(data), algorithm, version);

        using var document = await SendAsync(HttpMethod.Post, $"sign/{name}", request, cancellationToken);
        var signature = document.RootElement.GetProperty("data").GetProperty("signature").GetString()!;

        // Transit returns "vault:v<version>:<base64(signature)>"; the wire signature is the last segment.
        return Convert.FromBase64String(signature[(signature.LastIndexOf(':') + 1)..]);
    }

    // Transit sign-request field values. RSA sets signature_algorithm (PKCS#1 v1.5 / PSS); EC sets
    // marshaling_algorithm=jws so Transit returns the R||S form JWS needs instead of ASN.1 DER.
    private const string Pkcs1V15 = "pkcs1v15";
    private const string Pss = "pss";
    private const string Sha2With256 = "sha2-256";
    private const string Sha2With384 = "sha2-384";
    private const string Sha2With512 = "sha2-512";
    private const string JwsMarshaling = "jws";

    // Maps a JWS algorithm to the Transit sign request pinned to the given key version; an unmapped algorithm is
    // rejected. key_version pins the exact version the kid names, so the produce role signs with the active
    // version even when a newer version is already published but still propagating.
    private static VaultSignRequest BuildSignRequest(string input, string algorithm, int version)
    {
        // An algorithm decides two things independently: which digest, and how the signature is formed. RSA picks
        // a padding, EC picks an encoding, so the request differs by exactly one field between the families.
        var request = new VaultSignRequest
        {
            Input = input,
            HashAlgorithm = HashAlgorithmFor(algorithm),
            KeyVersion = version,
        };

        return algorithm switch
        {
            SigningAlgorithms.RS256 or SigningAlgorithms.RS384 or SigningAlgorithms.RS512
                => request with { SignatureAlgorithm = Pkcs1V15 },

            SigningAlgorithms.PS256 or SigningAlgorithms.PS384 or SigningAlgorithms.PS512
                => request with { SignatureAlgorithm = Pss },

            SigningAlgorithms.ES256 or SigningAlgorithms.ES384 or SigningAlgorithms.ES512
                => request with { MarshalingAlgorithm = JwsMarshaling },

            _ => throw new NotSupportedException($"The Vault Transit store does not sign '{algorithm}'."),
        };
    }

    private static string HashAlgorithmFor(string algorithm) => algorithm switch
    {
        SigningAlgorithms.RS256 or SigningAlgorithms.PS256 or SigningAlgorithms.ES256 => Sha2With256,
        SigningAlgorithms.RS384 or SigningAlgorithms.PS384 or SigningAlgorithms.ES384 => Sha2With384,
        SigningAlgorithms.RS512 or SigningAlgorithms.PS512 or SigningAlgorithms.ES512 => Sha2With512,

        _ => throw new NotSupportedException($"The Vault Transit store does not sign '{algorithm}'."),
    };

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

        var (name, version) = ParseKeyId(keyId);
        var request = new { ciphertext = $"vault:v{version}:{Convert.ToBase64String(encryptedKey)}" };

        var (status, document) = await TrySendAsync(HttpMethod.Post, $"decrypt/{name}", request, cancellationToken);
        using (document)
        {
            if (status == HttpStatusCode.BadRequest)
                return null;

            EnsureSuccess(status, document, $"decrypt/{name}");
            var plaintext = document!.RootElement.GetProperty("data").GetProperty("plaintext").GetString()!;
            return Convert.FromBase64String(plaintext);
        }
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
    /// Transit reports the key family in the "type" field ("ecdsa-p256", "rsa-2048"): match on the family prefix,
    /// not the exact curve or modulus size.
    /// </summary>
    private static class KeyFamilyTypes
    {
        public const string Ecdsa = "ecdsa";
        public const string Rsa = "rsa";
    }

    /// <summary>
    /// Enumerates every version of the Transit key as a public-only JWK (RSA or EC, per the Transit key type),
    /// each carrying the version-specific <c>kid</c> (<c>&lt;name&gt;:&lt;version&gt;</c>) and the version's
    /// creation time. Transit returns each version's public half as a PEM (SubjectPublicKeyInfo). Called at
    /// publication time, so JWKS publishing and signature verification run locally against the result and never
    /// touch this client on the hot path.
    /// </summary>
    public async IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
        string keyName,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var document = await SendAsync(HttpMethod.Get, $"keys/{keyName}", body: null, cancellationToken);
        var data = document.RootElement.GetProperty("data");
        var keyType = data.GetProperty("type").GetString()!;

        // Transit returns every version under "keys" as { "<version>": { public_key, creation_time } }. Publish
        // them all so a rotation overlaps; the kid names the version so a later sign/unwrap addresses it exactly.
        foreach (var version in data.GetProperty("keys").EnumerateObject())
        {
            var pem = version.Value.GetProperty("public_key").GetString()!;
            var createdAt = DateTimeOffset.Parse(
                version.Value.GetProperty("creation_time").GetString()!,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind);
            var publicKey = ImportPublicKey(keyType, pem) with { KeyId = $"{keyName}:{version.Name}" };
            yield return new KeyVersion(publicKey, createdAt);
        }
    }

    // The published kid is "<transit key name>:<version>"; split it to address the Transit key and pin the
    // version for a private operation. Transit key names contain no colon, so the last colon is the separator.
    private static (string Name, int Version) ParseKeyId(string keyId)
    {
        var separator = keyId.LastIndexOf(':');
        if (separator > 0 && int.TryParse(
                keyId.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var version))
            return (keyId[..separator], version);

        throw new InvalidOperationException(
            $"Malformed external key id '{keyId}'; expected '<name>:<version>' from GetKeyVersionsAsync.");
    }

    // Imports a Transit public key PEM (SubjectPublicKeyInfo) into a public-only JWK of the matching type.
    private static JsonWebKey ImportPublicKey(string keyType, string pem)
    {
        if (keyType.StartsWith(KeyFamilyTypes.Ecdsa, StringComparison.Ordinal))
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            return new EllipticCurveJsonWebKey().Apply(ecdsa.ExportParameters(false));
        }

        if (keyType.StartsWith(KeyFamilyTypes.Rsa, StringComparison.Ordinal))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return new RsaJsonWebKey().Apply(rsa.ExportParameters(false));
        }

        throw new NotSupportedException($"The Vault Transit store does not publish key type '{keyType}'.");
    }

    private async Task<JsonDocument> SendAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        var (status, document) = await TrySendAsync(method, path, body, cancellationToken);
        EnsureSuccess(status, document, path);
        return document!;
    }

    private async Task<(HttpStatusCode Status, JsonDocument? Document)> TrySendAsync(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
            request.Content = JsonContent.Create(body);

        using var response = await httpClient.SendAsync(request, cancellationToken);
        var payload = await response.Content.ReadAsStringAsync(cancellationToken);
        var document = string.IsNullOrEmpty(payload) ? null : JsonDocument.Parse(payload);
        return (response.StatusCode, document);
    }

    private static void EnsureSuccess(HttpStatusCode status, JsonDocument? document, string path)
    {
        if (status is >= HttpStatusCode.OK and < HttpStatusCode.Ambiguous)
            return;

        var errors = document?.RootElement.TryGetProperty("errors", out var e) == true ? e.ToString() : "(none)";
        throw new InvalidOperationException($"Vault Transit '{path}' failed with {(int)status}: {errors}");
    }
}
