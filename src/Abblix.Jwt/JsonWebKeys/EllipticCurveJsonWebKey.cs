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
    [JsonIgnore]
    public override bool HasPublicKey => X is { Length: > 0 } && Y is { Length: > 0 } && Curve != null;

    /// <inheritdoc/>
    /// <remarks>
    /// For Elliptic Curve keys, returns true if private key material (PrivateKey) is present.
    /// Private key enables decryption and signing operations.
    /// </remarks>
    [JsonIgnore]
    public override bool HasPrivateKey => PrivateKey is { Length: > 0 };

    /// <inheritdoc/>
    /// <remarks>
    /// Required EC members per RFC 7638 §3.2 in lexicographic order: <c>crv</c>,
    /// <c>kty</c>, <c>x</c>, <c>y</c>. The interpolated <c>crv</c> identifier and the
    /// base64url-encoded coordinates contain only characters that need no JSON escaping.
    /// </remarks>
    protected override string CanonicalJson()
        => $$"""{"crv":"{{Require(JsonWebKeyPropertyNames.Curve, Curve)}}","kty":"{{KeyType}}","x":"{{Encode(JsonWebKeyPropertyNames.EllipticCurveX, X)}}","y":"{{Encode(JsonWebKeyPropertyNames.EllipticCurveY, Y)}}"}""";
}
