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
/// Represents an Elliptic Curve JSON Web Key (JWK) containing EC-specific cryptographic parameters.
/// Supports both public and private EC keys per RFC 7518 Section 6.2.
/// </summary>
public sealed record EllipticCurveJsonWebKey : JsonWebKey
{
    /// <summary>
    /// The key type identifier for Elliptic Curve keys. Always returns "EC".
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.KeyType)]
    [JsonPropertyOrder(1)]
    [JsonInclude]
    public override string KeyType => JsonWebKeyTypes.EllipticCurve;

    /// <summary>
    /// X-coordinate for Elliptic Curve (x). Part of the Elliptic Curve public key.
    /// This is a required parameter for EC public keys.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.EllipticCurveX)]
    [JsonPropertyOrder(8)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? X { get; set; }

    /// <summary>
    /// Y-coordinate for Elliptic Curve (y). Part of the Elliptic Curve public key.
    /// This is a required parameter for EC public keys.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.EllipticCurveY)]
    [JsonPropertyOrder(9)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? Y { get; set; }

    /// <summary>
    /// Elliptic Curve Type (crv). Identifies the curve type for an Elliptic Curve key.
    /// Common values include "P-256", "P-384", "P-521" for NIST curves.
    /// This is a required parameter for EC keys.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.Curve)]
    [JsonPropertyOrder(10)]
    public string? Curve { get; set; }

    /// <summary>
    /// ECC Private Key (d). Represents the private part of an Elliptic Curve key.
    /// This parameter must be kept confidential and should only be present in private keys.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.PrivateExponent)]
    [JsonPropertyOrder(11)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? PrivateKey { get; set; }

    /// <summary>
    /// Prepares a sanitized version of the EC JWK that excludes private key information unless explicitly included.
    /// </summary>
    /// <param name="includePrivateKeys">Whether to include private key data in the sanitized output.</param>
    /// <returns>
    /// A new instance of <see cref="EllipticCurveJsonWebKey"/> with or without private key data based on the input parameter.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when includePrivateKeys is true but the key contains no private key data.
    /// </exception>
    public override JsonWebKey Sanitize(bool includePrivateKeys)
    {
        return includePrivateKeys switch
        {
            true when PrivateKey is { Length: > 0 } => this,
            true => throw new InvalidOperationException($"There is no private key for kid={KeyId}"),
            false => this with
            {
                PrivateKey = null,
            }
        };
    }

    /// <inheritdoc/>
    /// <remarks>
    /// For Elliptic Curve keys, returns true if public key material (X, Y, and Curve) is present.
    /// Public key enables encryption and signature verification operations.
    /// </remarks>
    public override bool HasPublicKey => X is { Length: > 0 } && Y is { Length: > 0 } && Curve != null;

    /// <inheritdoc/>
    /// <remarks>
    /// For Elliptic Curve keys, returns true if private key material (PrivateKey) is present.
    /// Private key enables decryption and signing operations.
    /// </remarks>
    public override bool HasPrivateKey => PrivateKey is { Length: > 0 };
}
