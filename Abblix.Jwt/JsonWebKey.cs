// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Jwt;

//TODO consider to split this class into specialized subclasses (RSA/EllipticCurve)
/// <summary>
/// Represents a JSON Web Key (JWK), a versatile structure for representing cryptographic keys using JSON.
/// It supports various cryptographic algorithms, including RSA and Elliptic Curve, and can represent both
/// public and private keys. JWKs are crucial for digital signatures, encryption, and ensuring secure
/// communication in web-based protocols.
/// </summary>
public record JsonWebKey
{
    /// <summary>
    /// Identifies the cryptographic algorithm family used with the key, such as RSA or EC (Elliptic Curve),
    /// specifying the key's type and its intended cryptographic use.
    /// </summary>
    [JsonPropertyName("kty")]
    [JsonPropertyOrder(1)]
    public string? KeyType { get; set; }

    /// <summary>
    /// Indicates the intended use of the key, for example, "sig" (signature) for signing operations or
    /// "enc" (encryption) for encryption operations, guiding clients on how to use the key appropriately.
    /// </summary>
    [JsonPropertyName("use")]
    [JsonPropertyOrder(2)]
    public string? Usage { get; set; }

    /// <summary>
    /// Specifies the algorithm intended for use with the key, aligning with JWT and JWA specifications
    /// to ensure interoperability and secure key management.
    /// </summary>
    [JsonPropertyName("alg")]
    [JsonPropertyOrder(3)]
    public string? Algorithm { get; set; }

    /// <summary>
    /// A unique identifier for the key, facilitating key selection and management in multi-key environments,
    /// enabling clients and servers to reference and utilize the correct key for cryptographic operations.
    /// </summary>
    [JsonPropertyName("kid")]
    [JsonPropertyOrder(4)]
    public string? KeyId { get; set; }

    /// <summary>
    /// Contains a chain of one or more PKIX certificates (RFC 5280), offering a method to associate X.509
    /// certificates with the key for validation and trust chain establishment in secure communications.
    /// </summary>
    [JsonPropertyName("x5c")]
    [JsonPropertyOrder(5)]
    [JsonConverter(typeof(ArrayConverter<byte[]?, Base64UrlTextEncoderConverter>))]
    public byte[][]? Certificates { get; set; }

    /// <summary>
    /// A base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate, providing a compact
    /// means to associate a certificate with the JWK for verification purposes without transmitting the full certificate.
    /// </summary>
    [JsonPropertyName("x5t")]
    [JsonPropertyOrder(5)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? Thumbprint { get; set; }

    /// <summary>
    /// RSA Public Key Exponent (e). Part of the RSA public key.
    /// </summary>
    [JsonPropertyName("e")]
    [JsonPropertyOrder(6)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? RsaExponent { get; set; }

    /// <summary>
    /// RSA Public Key Modulus (n). Part of the RSA public key.
    /// </summary>
    [JsonPropertyName("n")]
    [JsonPropertyOrder(7)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? RsaModulus { get; set; }

    /// <summary>
    /// X-coordinate for Elliptic Curve (x). Part of the Elliptic Curve public key.
    /// </summary>
    [JsonPropertyName("x")]
    [JsonPropertyOrder(8)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? EllipticalCurvePointX { get; set; }

    /// <summary>
    /// Y-coordinate for Elliptic Curve (y). Part of the Elliptic Curve public key.
    /// </summary>
    [JsonPropertyName("y")]
    [JsonPropertyOrder(9)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? EllipticalCurvePointY { get; set; }

    /// <summary>
    /// Elliptic Curve Type (crv). Identifies the curve type for an Elliptic Curve key.
    /// </summary>
    [JsonPropertyName("crv")]
    [JsonPropertyOrder(10)]
    public string? EllipticalCurveType { get; set; }

    /// <summary>
    /// ECC Private Key or RSA Private Exponent (d). Represents the private part of an RSA or Elliptic Curve key.
    /// </summary>
    [JsonPropertyName("d")]
    [JsonPropertyOrder(11)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? PrivateKey { get; set; }

    /// <summary>
    /// RSA First Prime Factor (p). Part of the RSA private key.
    /// </summary>
    [JsonPropertyName("p")]
    [JsonPropertyOrder(12)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? FirstPrimeFactor { get; set; }

    /// <summary>
    /// RSA Second Prime Factor (q). Part of the RSA private key.
    /// </summary>
    [JsonPropertyName("q")]
    [JsonPropertyOrder(13)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? SecondPrimeFactor { get; set; }

    /// <summary>
    /// RSA First Factor CRT Exponent (dp). Part of the RSA private key in Chinese Remainder Theorem (CRT) format.
    /// </summary>
    [JsonPropertyName("dp")]
    [JsonPropertyOrder(14)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? FirstFactorCrtExponent { get; set; }

    /// <summary>
    /// RSA Second Factor CRT Exponent (dq). Part of the RSA private key in CRT format.
    /// </summary>
    [JsonPropertyName("dq")]
    [JsonPropertyOrder(15)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? SecondFactorCrtExponent { get; set; }

    /// <summary>
    /// RSA First CRT Coefficient (qi). Part of the RSA private key in CRT format.
    /// </summary>
    [JsonPropertyName("qi")]
    [JsonPropertyOrder(16)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? FirstCrtCoefficient { get; set; }

    /// <summary>
    /// Prepares a sanitized version of the JWK that excludes private key information unless explicitly included,
    /// suitable for public sharing while preserving the integrity of sensitive data.
    /// </summary>
    /// <param name="includePrivateKeys">Whether to include private key data in the sanitized output.</param>
    /// <returns>
    /// A new instance of <see cref="JsonWebKey"/> with or without private key data based on the input parameter.
    /// </returns>
    public JsonWebKey Sanitize(bool includePrivateKeys)
    {
        return includePrivateKeys switch
        {
            true when PrivateKey is { Length: > 0} => this,
            true => throw new InvalidOperationException($"There is no private key for kid={KeyId}"),
            false => this with
            {
                PrivateKey = null,
                FirstCrtCoefficient = null,
                FirstPrimeFactor = null,
                FirstFactorCrtExponent = null,
                SecondPrimeFactor = null,
                SecondFactorCrtExponent = null,
            }
        };
    }
}
