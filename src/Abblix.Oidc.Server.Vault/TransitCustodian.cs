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
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Abblix.Jwt;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Vault;

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
    private readonly HttpClient _httpClient = httpClientFactory.CreateClient(Transport.ClientName);

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
        var (name, version) = ParseKeyId(keyId);
        var request = BuildSignRequest(Convert.ToBase64String(data), algorithm, version);
        var path = $"{Mount}/sign/{name}";

        using var response = await _httpClient.SendAsync(HttpMethod.Post, path, request, cancellationToken);
        response.EnsureSuccess(path);

        var signature = response.Body(path).RootElement.GetProperty("data").GetProperty("signature").GetString()!;

        // Transit returns "vault:v<version>:<base64(signature)>"; the wire signature is the last segment.
        return Convert.FromBase64String(signature[(signature.LastIndexOf(':') + 1)..]);
    }

    private static class SignatureAlgorithms
    {
        public const string Pkcs1V15 = "pkcs1v15";
        public const string Pss = "pss";
    }

    private static class HashAlgorithms
    {
        public const string Sha2With256 = "sha2-256";
        public const string Sha2With384 = "sha2-384";
        public const string Sha2With512 = "sha2-512";
    }

    private static class MarshalingAlgorithms
    {
        public const string Jws = "jws";
    }

    // Maps a JWS algorithm to the Transit sign request pinned to the given key version; an unmapped algorithm is
    // rejected. key_version pins the exact version the kid names, so the produce role signs with the active
    // version even when a newer version is already published but still propagating.
    private static SignRequest BuildSignRequest(string input, string algorithm, int version)
    {
        // An algorithm decides two things independently: which digest, and how the signature is formed. RSA picks
        // a padding, EC picks an encoding, so the request differs by exactly one field between the families.
        var request = new SignRequest
        {
            Input = input,
            HashAlgorithm = HashAlgorithmFor(algorithm),
            KeyVersion = version,
        };

        // Transit sign-request field values. RSA sets signature_algorithm (PKCS#1 v1.5 / PSS); EC sets
        // marshaling_algorithm=jws so Transit returns the R||S form JWS needs instead of ASN.1 DER.
        return algorithm switch
        {
            SigningAlgorithms.RS256 or SigningAlgorithms.RS384 or SigningAlgorithms.RS512
                => request with { SignatureAlgorithm = SignatureAlgorithms.Pkcs1V15 },

            SigningAlgorithms.PS256 or SigningAlgorithms.PS384 or SigningAlgorithms.PS512
                => request with { SignatureAlgorithm = SignatureAlgorithms.Pss },

            SigningAlgorithms.ES256 or SigningAlgorithms.ES384 or SigningAlgorithms.ES512
                => request with { MarshalingAlgorithm = MarshalingAlgorithms.Jws },

            _ => throw new NotSupportedException($"The Vault Transit store does not sign '{algorithm}'."),
        };
    }

    private static string HashAlgorithmFor(string algorithm) => algorithm switch
    {
        SigningAlgorithms.RS256 or SigningAlgorithms.PS256 or SigningAlgorithms.ES256 => HashAlgorithms.Sha2With256,
        SigningAlgorithms.RS384 or SigningAlgorithms.PS384 or SigningAlgorithms.ES384 => HashAlgorithms.Sha2With384,
        SigningAlgorithms.RS512 or SigningAlgorithms.PS512 or SigningAlgorithms.ES512 => HashAlgorithms.Sha2With512,

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
        var path = $"{Mount}/decrypt/{name}";

        using var response = await _httpClient.SendAsync(HttpMethod.Post, path, request, cancellationToken);
        if (response.Status == HttpStatusCode.BadRequest)
        {
            LogUnwrapRejected(keyId);
            return null;
        }

        response.EnsureSuccess(path);
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
        var path = $"{Mount}/keys/{keyName}";
        using var response = await _httpClient.SendAsync(HttpMethod.Get, path, body: null, cancellationToken);
        response.EnsureSuccess(path);

        var data = response.Body(path).RootElement.GetProperty("data");
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
}
