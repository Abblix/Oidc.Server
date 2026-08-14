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

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Abblix.Utils.Json;
using Abblix.Utils.Polyfills;

namespace Abblix.Jwt;

/// <summary>
/// Base class representing a JSON Web Key (JWK), a versatile structure for representing cryptographic keys using JSON.
/// JWKs are crucial for digital signatures, encryption, and ensuring secure communication in web-based protocols.
/// </summary>
/// <remarks>
/// This is an abstract base class. Use specific subclasses for different key types:
/// <list type="bullet">
/// <item><see cref="RsaJsonWebKey"/> for RSA keys</item>
/// <item><see cref="EllipticCurveJsonWebKey"/> for Elliptic Curve keys</item>
/// <item><see cref="OctetJsonWebKey"/> for symmetric keys (oct)</item>
/// </list>
/// </remarks>
[JsonConverter(typeof(JsonWebKeyConverter))]
public abstract record JsonWebKey
{
    /// <summary>
    /// Prevents external inheritance. Only types in this assembly can inherit from JsonWebKey.
    /// </summary>
    private protected JsonWebKey()
    {
    }

    /// <summary>
    /// Identifies the cryptographic algorithm family used with the key, such as RSA, EC (Elliptic Curve), or oct (Octet Sequence),
    /// specifying the key's type and its intended cryptographic use.
    /// </summary>
    /// <remarks>
    /// This property is marked with <see cref="JsonIgnoreAttribute"/> on the base class to prevent conflicts
    /// with the custom <see cref="JsonWebKeyConverter"/>. Derived types override this property with
    /// <c>[JsonPropertyName("kty")]</c> and <c>[JsonInclude]</c> attributes. The custom converter ensures
    /// "kty" is always serialized by serializing the concrete type's properties, maintaining RFC 7517 compliance.
    /// </remarks>
    [JsonIgnore]
    public abstract string KeyType { get; }

    /// <summary>
    /// Indicates the intended use of the key, for example, "sig" (signature) for signing operations or
    /// "enc" (encryption) for encryption operations, guiding clients on how to use the key appropriately.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.Usage)]
    [JsonPropertyOrder(2)]
    public string? Usage { get; set; }

    /// <summary>
    /// Specifies the algorithm intended for use with the key, aligning with JWT and JWA specifications
    /// to ensure interoperability and secure key management.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.Algorithm)]
    [JsonPropertyOrder(3)]
    public string? Algorithm { get; set; }

    /// <summary>
    /// A unique identifier for the key, facilitating key selection and management in multi-key environments,
    /// enabling clients and servers to reference and utilize the correct key for cryptographic operations.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.KeyId)]
    [JsonPropertyOrder(4)]
    public string? KeyId { get; set; }

    /// <summary>
    /// Contains a chain of one or more PKIX certificates (RFC 5280), offering a method to associate X.509
    /// certificates with the key for validation and trust chain establishment in secure communications.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.Certificates)]
    [JsonPropertyOrder(5)]
    [JsonConverter(typeof(ArrayConverter<byte[]?, Base64UrlTextEncoderConverter>))]
    public byte[][]? Certificates { get; set; }

    /// <summary>
    /// A base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate, providing a compact
    /// means to associate a certificate with the JWK for verification purposes without transmitting the full certificate.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.Thumbprint)]
    [JsonPropertyOrder(5)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? Thumbprint { get; set; }

    /// <summary>
    /// Prepares a sanitized version of the JWK that excludes private key information unless explicitly included,
    /// suitable for public sharing while preserving the integrity of sensitive data.
    /// </summary>
    /// <param name="includePrivateKeys">Whether to include private key data in the sanitized output.</param>
    /// <returns>
    /// A new instance of <see cref="JsonWebKey"/> with or without private key data based on the input parameter.
    /// </returns>
    public abstract JsonWebKey Sanitize(bool includePrivateKeys);

    /// <summary>
    /// Checks if the key contains public key material.
    /// </summary>
    [JsonIgnore]
    public abstract bool HasPublicKey { get; }

    /// <summary>
    /// Checks if the key contains private key material.
    /// </summary>
    [JsonIgnore]
    public abstract bool HasPrivateKey { get; }

    /// <summary>
    /// Builds the canonical-JSON form of this key per RFC 7638 §3.2: the required members
    /// for this <c>kty</c>, in lexicographic order, with no whitespace. Optional members
    /// (<c>use</c>, <c>alg</c>, <c>kid</c>, certificate metadata) must NOT enter the form.
    /// </summary>
    /// <returns>The canonical-JSON string fed into the SHA-256 hash by
    /// <see cref="ComputeJwkThumbprint"/>.</returns>
    /// <exception cref="InvalidOperationException">A member required by the concrete
    /// subtype is missing.</exception>
    protected abstract string CanonicalJson();

    /// <summary>
    /// Computes the JWK Thumbprint of this key per RFC 7638 §3 as the raw 32-byte SHA-256
    /// digest of the canonical-JSON form built by <see cref="CanonicalJson"/>.
    /// </summary>
    /// <remarks>
    /// The thumbprint is computed at runtime from the public-key material; it is not a
    /// stored member on the JWK and is distinct from the X.509 certificate thumbprints
    /// <c>x5t</c> (RFC 7517 §4.8) and <c>x5t#S256</c> (RFC 7517 §4.9), which hash the
    /// certificate, not the key. OAuth 2.0 DPoP (RFC 9449) uses this value for
    /// <c>cnf.jkt</c> and the <c>dpop_jkt</c> request parameter.
    /// </remarks>
    /// <returns>The 32-byte SHA-256 digest.</returns>
    /// <exception cref="InvalidOperationException">A required member
    /// (per RFC 7638 §3.2) is missing on this key.</exception>
    public byte[] ComputeJwkThumbprint()
    {
        var canonical = CanonicalJson();
        return SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
    }

    /// <summary>
    /// Computes the JWK Thumbprint of this key per RFC 7638 §3 and returns the
    /// base64url-encoded form, which is the wire shape used by DPoP <c>cnf.jkt</c> and
    /// the <c>dpop_jkt</c> authorization-request parameter.
    /// </summary>
    /// <returns>The base64url-encoded SHA-256 digest of the canonical-JSON form.</returns>
    /// <exception cref="InvalidOperationException">A required member
    /// (per RFC 7638 §3.2) is missing on this key.</exception>
    public string ComputeJwkThumbprintBase64Url()
        => Base64Url.EncodeToString(ComputeJwkThumbprint());

    /// <summary>
    /// Throws if a required byte-array member is missing on the key, otherwise returns its base64url-encoded form.
    /// </summary>
    /// <param name="name">The JWK wire name of the member being encoded
    /// (use a constant from <see cref="JsonWebKeyPropertyNames"/>).
    /// Appears verbatim in the exception message.</param>
    /// <param name="value">The byte content of the member.</param>
    /// <returns>The base64url-encoded form of <paramref name="value"/>.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="value"/> is
    /// <c>null</c>.</exception>
    protected static string Encode(string name, byte[]? value)
        => Base64Url.EncodeToString(Require(name, value));

    /// <summary>
    /// Throws if a required member is missing on the key, otherwise returns the value unchanged.
    /// Used for members whose wire form is already a string (such as the EC <c>crv</c> identifier).
    /// Callers that need base64url encoding for byte-array members go through <see cref="Encode"/>,
    /// which builds on top of it.
    /// </summary>
    /// <typeparam name="T">The type of the member being checked.</typeparam>
    /// <param name="name">The JWK wire name of the member (use a constant from
    /// <see cref="JsonWebKeyPropertyNames"/>). Appears verbatim in the exception
    /// message.</param>
    /// <param name="value">The value of the member.</param>
    /// <returns><paramref name="value"/> when not <c>null</c>.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="value"/> is
    /// <c>null</c>.</exception>
    protected static T Require<T>(string name, T? value) =>
        value ?? throw new InvalidOperationException($"JWK Thumbprint requires the '{name}' member for a key.");
}
