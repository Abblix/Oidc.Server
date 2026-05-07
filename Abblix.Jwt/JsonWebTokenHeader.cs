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

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Represents the header part of a JSON Web Token (JWT), containing metadata about the token
/// such as the type and the algorithm used for signing.
/// </summary>
/// <remarks>
/// The JWT header typically specifies the cryptographic operations applied to the JWT
/// and can also include additional properties defined or required by the application.
/// </remarks>
public class JsonWebTokenHeader(JsonObject json)
{
    /// <summary>
    /// The underlying mutable JSON object backing the strongly-typed accessors on this header.
    /// Use this when reading or writing custom header parameters that are not modeled as properties.
    /// </summary>
    public JsonObject Json { get; } = json;

    /// <summary>
    /// The type of the JWT, typically "JWT" or a similar identifier.
    /// This field is optional and used to declare the media type of the JWT.
    /// </summary>
    /// <remarks>
    /// The 'typ' parameter is recommended when the JWT is embedded in places not inherently
    /// carrying this information, helping recipients process the JWT type accordingly.
    /// </remarks>
    public string? Type
    {
        get => Json.GetProperty<string>(JwtClaimTypes.Type);
        set => Json.SetProperty(JwtClaimTypes.Type, value);
    }

    /// <summary>
    /// The algorithm used to sign the JWT, indicating how the token is secured.
    /// </summary>
    /// <remarks>
    /// The 'alg' parameter identifies the cryptographic algorithm used to secure the JWT.
    /// Common algorithms include HS256, RS256, and ES256. It is crucial for verifying the JWT integrity.
    /// Per RFC 7515 Section 4.1.1, this parameter is REQUIRED.
    /// </remarks>
    public string? Algorithm
    {
        get => Json.GetProperty<string>(JwtClaimTypes.Algorithm);
        set => Json.SetProperty(JwtClaimTypes.Algorithm, value);
    }

    /// <summary>
    /// The key ID that indicates which key was used to secure the JWT.
    /// </summary>
    /// <remarks>
    /// The 'kid' parameter is a hint indicating which specific key from a JWKS was used to sign the JWT.
    /// This is particularly useful when the issuer has multiple keys and the verifier needs to
    /// identify the correct key for signature verification.
    /// </remarks>
    public string? KeyId
    {
        get => Json.GetProperty<string>(JwtClaimTypes.KeyId);
        set => Json.SetProperty(JwtClaimTypes.KeyId, value);
    }

    /// <summary>
    /// The content encryption algorithm used for JWE (JSON Web Encryption).
    /// </summary>
    /// <remarks>
    /// The 'enc' parameter identifies the content encryption algorithm used to encrypt the plaintext
    /// to produce the JWE ciphertext and authentication tag. Common algorithms include A128CBC-HS256,
    /// A192CBC-HS384, A256CBC-HS512, A128GCM, A192GCM, and A256GCM.
    /// </remarks>
    public string? EncryptionAlgorithm
    {
        get => Json.GetProperty<string>(JwtClaimTypes.EncryptionAlgorithm);
        set => Json.SetProperty(JwtClaimTypes.EncryptionAlgorithm, value);
    }

    /// <summary>
    /// The 'crit' (Critical) header parameter (RFC 7515 §4.1.11): names of JOSE header parameters
    /// that the recipient MUST understand and process. Returns null when 'crit' is absent.
    /// </summary>
    /// <exception cref="JsonException">Thrown when 'crit' is present but is not a JSON array of strings.</exception>
    [SuppressMessage("Sonar Bug", "S2372:Exceptions should not be thrown from property getters",
        Justification = "JsonWebTokenHeader is a typed view over untrusted external JSON. Returning null on a malformed 'crit' would silently coerce a producer-spec violation into accepted state — RFC 7515 §4.1.11 requires the recipient to reject it, and the validator's critical-headers pass relies on this getter surfacing the parse error.")]
    public IReadOnlyList<string>? Critical
    {
        get
        {
            if (!Json.TryGetPropertyValue(JwtClaimTypes.Critical, out var node) || node is null)
                return null;
            if (node is not JsonArray array)
                throw new JsonException($"'{JwtClaimTypes.Critical}' header must be a JSON array");

            var result = new string[array.Count];
            for (var i = 0; i < array.Count; i++)
            {
                if (array[i] is not JsonValue value || !value.TryGetValue<string>(out var name))
                    throw new JsonException($"'{JwtClaimTypes.Critical}' header must contain only strings");
                result[i] = name;
            }
            return result;
        }
        set
        {
            if (value is null)
            {
                Json.Remove(JwtClaimTypes.Critical);
                return;
            }
            var array = new JsonArray();
            foreach (var name in value)
                array.Add(name);
            Json[JwtClaimTypes.Critical] = array;
        }
    }

    /// <summary>
    /// The 'jku' (JWK Set URL) header parameter (RFC 7515 §4.1.2): a URI referring to a JSON Web
    /// Key Set whose keys the issuer claims are candidates for verifying the JWS. The library
    /// only exposes the URI; it does not fetch the URL — the host is responsible for trust and
    /// transport per RFC 7515 §8 (TLS with server identity validation per RFC 6125).
    /// </summary>
    public Uri? JwkSetUrl
    {
        get
        {
            var raw = Json.GetProperty<string>(JwtClaimTypes.JwkSetUrl);
            return raw is not null ? new Uri(raw) : null;
        }
        set => Json.SetProperty(JwtClaimTypes.JwkSetUrl, value?.ToString());
    }

    /// <summary>
    /// The 'jwk' (JSON Web Key) header parameter (RFC 7515 §4.1.3): the public key used to
    /// verify the JWS, embedded directly in the JOSE header as a JWK. Returns null when
    /// 'jwk' is absent. Trust is the consumer's responsibility — for example, DPoP (RFC 9449)
    /// binds this key to the request via a separate confirmation claim.
    /// </summary>
    /// <exception cref="JsonException">Thrown when 'jwk' is present but is not a valid JWK (e.g. unknown 'kty').</exception>
    [SuppressMessage("Sonar Bug", "S2372:Exceptions should not be thrown from property getters",
        Justification = "Deserialize<JsonWebKey> can throw JsonException when 'jwk' is malformed. Returning null on a malformed JWK would let a downstream consumer (DPoP, federation) silently treat the absence of trust material as success — the parse error must surface.")]
    public JsonWebKey? VerificationKey
    {
        get => Json.TryGetPropertyValue(JwtClaimTypes.JsonWebKeyHeader, out var node) && node is JsonObject obj
                ? obj.Deserialize<JsonWebKey>()
                : null;
        set
        {
            if (value is not null)
                Json[JwtClaimTypes.JsonWebKeyHeader] = JsonSerializer.SerializeToNode(value);
            else
                Json.Remove(JwtClaimTypes.JsonWebKeyHeader);
        }
    }

    /// <summary>
    /// The 'x5u' (X.509 URL) header parameter (RFC 7515 §4.1.5): a URI referring to an X.509
    /// public-key certificate or certificate chain corresponding to the key used for the JWS
    /// signature. Same caveat as <see cref="JwkSetUrl"/> — the library does not fetch.
    /// </summary>
    public Uri? CertificatesUrl
    {
        get
        {
            var raw = Json.GetProperty<string>(JwtClaimTypes.X509Url);
            return raw is null ? null : new Uri(raw);
        }
        set => Json.SetProperty(JwtClaimTypes.X509Url, value?.ToString());
    }

    /// <summary>
    /// The 'x5c' (X.509 Certificate Chain) header parameter (RFC 7515 §4.1.6): an X.509
    /// certificate chain as a JSON array of base64-encoded DER certificates, the first being
    /// the leaf. Returns the raw base64 strings; consumers are responsible for decoding to
    /// <c>X509Certificate2</c> and validating the chain per RFC 5280.
    /// </summary>
    /// <exception cref="JsonException">Thrown when 'x5c' is present but is not a JSON array of strings.</exception>
    [SuppressMessage("Sonar Bug", "S2372:Exceptions should not be thrown from property getters",
        Justification = "Returning null on a malformed 'x5c' array would let a host treat 'no certificate chain available' identically to 'producer sent a wrong shape', collapsing two distinct conditions a chain-validating consumer must distinguish.")]
    public IReadOnlyList<string>? Certificates
    {
        get
        {
            if (!Json.TryGetPropertyValue(JwtClaimTypes.X509CertificateChain, out var node) || node is null)
                return null;
            if (node is not JsonArray array)
                throw new JsonException($"'{JwtClaimTypes.X509CertificateChain}' header must be a JSON array");

            var result = new string[array.Count];
            for (var i = 0; i < array.Count; i++)
            {
                if (array[i] is not JsonValue value || !value.TryGetValue<string>(out var cert))
                    throw new JsonException($"'{JwtClaimTypes.X509CertificateChain}' header must contain only strings");
                result[i] = cert;
            }
            return result;
        }
        set
        {
            if (value is null)
            {
                Json.Remove(JwtClaimTypes.X509CertificateChain);
                return;
            }
            var array = new JsonArray();
            foreach (var cert in value)
                array.Add(cert);
            Json[JwtClaimTypes.X509CertificateChain] = array;
        }
    }

    /// <summary>
    /// The 'x5t' (X.509 SHA-1 Thumbprint) header parameter (RFC 7515 §4.1.7): base64url-encoded
    /// SHA-1 digest of the DER-encoded leaf certificate. Per RFC 7515 §10.11, SHA-1 is
    /// discouraged because of cryptographic weaknesses — prefer <see cref="CertificateSha256Thumbprint"/>
    /// for new deployments. The library exposes 'x5t' for inspection of legacy producers.
    /// </summary>
    public string? CertificateSha1Thumbprint
    {
        get => Json.GetProperty<string>(JwtClaimTypes.X509Sha1Thumbprint);
        set => Json.SetProperty(JwtClaimTypes.X509Sha1Thumbprint, value);
    }

    /// <summary>
    /// The 'x5t#S256' (X.509 SHA-256 Thumbprint) header parameter (RFC 7515 §4.1.8):
    /// base64url-encoded SHA-256 digest of the DER-encoded leaf certificate. The C# member
    /// name strips the '#' character (illegal in identifiers); the JSON literal stays
    /// 'x5t#S256' as defined by the spec.
    /// </summary>
    public string? CertificateSha256Thumbprint
    {
        get => Json.GetProperty<string>(JwtClaimTypes.X509Sha256Thumbprint);
        set => Json.SetProperty(JwtClaimTypes.X509Sha256Thumbprint, value);
    }
}
