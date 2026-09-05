// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
            true when HasPrivateKey => this,
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
    [JsonIgnore]
    public override bool HasPublicKey => Modulus is { Length: > 0 } && Exponent is { Length: > 0 };

    /// <inheritdoc/>
    /// <remarks>
    /// For RSA keys, returns true if any RFC 7518 §6.3.2 private-key member is present -
    /// not just <c>d</c>. The DPoP §4.2 «MUST NOT contain private key» check needs to
    /// catch a JWK that omits <c>d</c> but still leaks CRT factors (<c>p</c>, <c>q</c>,
    /// <c>dp</c>, <c>dq</c>, <c>qi</c>), since those alone reconstruct the private key.
    /// </remarks>
    [JsonIgnore]
    public override bool HasPrivateKey
        => PrivateExponent is { Length: > 0 }
        || FirstPrimeFactor is { Length: > 0 }
        || SecondPrimeFactor is { Length: > 0 }
        || FirstFactorCrtExponent is { Length: > 0 }
        || SecondFactorCrtExponent is { Length: > 0 }
        || FirstCrtCoefficient is { Length: > 0 };

    /// <inheritdoc/>
    /// <remarks>
    /// Required RSA members per RFC 7638 §3.2 in lexicographic order: <c>e</c>,
    /// <c>kty</c>, <c>n</c>. Both base64url-encoded values contain only characters that
    /// need no JSON escaping.
    /// </remarks>
    protected override string CanonicalJson()
        => $$"""{"e":"{{Encode(JsonWebKeyPropertyNames.Exponent, Exponent)}}","kty":"{{KeyType}}","n":"{{Encode(JsonWebKeyPropertyNames.Modulus, Modulus)}}"}""";
}
