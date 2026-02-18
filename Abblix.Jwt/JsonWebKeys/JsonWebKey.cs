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

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

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
}
