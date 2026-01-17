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
/// Represents an RSA JSON Web Key (JWK) containing RSA-specific cryptographic parameters.
/// Supports both public and private RSA keys per RFC 7518 Section 6.3.
/// </summary>
public sealed record RsaJsonWebKey : JsonWebKey
{
    /// <summary>
    /// The key type identifier for RSA keys. Always returns "RSA".
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.KeyType)]
    [JsonPropertyOrder(1)]
    [JsonInclude]
    public override string KeyType => JsonWebKeyTypes.Rsa;

    /// <summary>
    /// RSA Public Key Exponent (e). Part of the RSA public key.
    /// This is a required parameter for RSA public keys.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.Exponent)]
    [JsonPropertyOrder(6)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? Exponent { get; set; }

    /// <summary>
    /// RSA Public Key Modulus (n). Part of the RSA public key.
    /// This is a required parameter for RSA public keys.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.Modulus)]
    [JsonPropertyOrder(7)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? Modulus { get; set; }

    /// <summary>
    /// RSA Private Exponent (d). Part of the RSA private key.
    /// This parameter must be kept confidential and should only be present in private keys.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.PrivateExponent)]
    [JsonPropertyOrder(11)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? PrivateExponent { get; set; }

    /// <summary>
    /// RSA First Prime Factor (p). Part of the RSA private key.
    /// Used in Chinese Remainder Theorem (CRT) optimization for RSA operations.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.FirstPrimeFactor)]
    [JsonPropertyOrder(12)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? FirstPrimeFactor { get; set; }

    /// <summary>
    /// RSA Second Prime Factor (q). Part of the RSA private key.
    /// Used in Chinese Remainder Theorem (CRT) optimization for RSA operations.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.SecondPrimeFactor)]
    [JsonPropertyOrder(13)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? SecondPrimeFactor { get; set; }

    /// <summary>
    /// RSA First Factor CRT Exponent (dp). Part of the RSA private key in Chinese Remainder Theorem (CRT) format.
    /// Computed as d mod (p-1), where d is the private exponent and p is the first prime factor.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.FirstFactorCrtExponent)]
    [JsonPropertyOrder(14)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? FirstFactorCrtExponent { get; set; }

    /// <summary>
    /// RSA Second Factor CRT Exponent (dq). Part of the RSA private key in CRT format.
    /// Computed as d mod (q-1), where d is the private exponent and q is the second prime factor.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.SecondFactorCrtExponent)]
    [JsonPropertyOrder(15)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? SecondFactorCrtExponent { get; set; }

    /// <summary>
    /// RSA First CRT Coefficient (qi). Part of the RSA private key in CRT format.
    /// Computed as q^(-1) mod p, the modular multiplicative inverse of q modulo p.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.FirstCrtCoefficient)]
    [JsonPropertyOrder(16)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? FirstCrtCoefficient { get; set; }

    /// <summary>
    /// Prepares a sanitized version of the RSA JWK that excludes private key information unless explicitly included.
    /// </summary>
    /// <param name="includePrivateKeys">Whether to include private key data in the sanitized output.</param>
    /// <returns>
    /// A new instance of <see cref="RsaJsonWebKey"/> with or without private key data based on the input parameter.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when includePrivateKeys is true but the key contains no private key data.
    /// </exception>
    public override JsonWebKey Sanitize(bool includePrivateKeys)
    {
        return includePrivateKeys switch
        {
            true when PrivateExponent is { Length: > 0 } => this,
            true => throw new InvalidOperationException($"There is no private key for kid={KeyId}"),
            false => this with
            {
                PrivateExponent = null,
                FirstCrtCoefficient = null,
                FirstPrimeFactor = null,
                FirstFactorCrtExponent = null,
                SecondPrimeFactor = null,
                SecondFactorCrtExponent = null,
            }
        };
    }

    /// <inheritdoc/>
    /// <remarks>
    /// For RSA keys, returns true if public key material (Modulus and Exponent) is present.
    /// Public key enables encryption and signature verification operations.
    /// </remarks>
    public override bool HasPublicKey => Modulus is { Length: > 0 } && Exponent is { Length: > 0 };

    /// <inheritdoc/>
    /// <remarks>
    /// For RSA keys, returns true if private key material (PrivateExponent) is present.
    /// Private key enables decryption and signing operations.
    /// </remarks>
    public override bool HasPrivateKey => PrivateExponent is { Length: > 0 };
}
