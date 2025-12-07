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
/// Represents a Symmetric JSON Web Key (JWK) containing symmetric key material for algorithms like HMAC.
/// Supports symmetric keys per RFC 7518 Section 6.4.
/// </summary>
public sealed record OctetJsonWebKey : JsonWebKey
{
    /// <summary>
    /// The key type identifier for symmetric (Octet Sequence) keys. Always returns "oct".
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.KeyType)]
    [JsonPropertyOrder(1)]
    [JsonInclude]
    public override string KeyType => JsonWebKeyTypes.Octet;

    /// <summary>
    /// Symmetric Key Value (k). Used for oct (Octet Sequence) keys, which are symmetric keys
    /// used in algorithms like HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512.
    /// This is a required parameter for symmetric keys and must be kept confidential.
    /// </summary>
    [JsonPropertyName(JsonWebKeyPropertyNames.KeyValue)]
    [JsonPropertyOrder(17)]
    [JsonConverter(typeof(Base64UrlTextEncoderConverter))]
    public byte[]? KeyValue { get; set; }

    /// <summary>
    /// Prepares a sanitized version of the symmetric JWK that excludes the key value unless explicitly included.
    /// </summary>
    /// <param name="includePrivateKeys">Whether to include the symmetric key value in the sanitized output.</param>
    /// <returns>
    /// A new instance of <see cref="OctetJsonWebKey"/> with or without the key value based on the input parameter.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when includePrivateKeys is true but the key contains no key value.
    /// </exception>
    /// <remarks>
    /// For symmetric keys, the key value is always considered sensitive and should be treated
    /// as private key material.
    /// </remarks>
    public override JsonWebKey Sanitize(bool includePrivateKeys)
    {
        return includePrivateKeys switch
        {
            true when KeyValue is { Length: > 0 } => this,
            true => throw new InvalidOperationException($"There is no key value for kid={KeyId}"),
            false => this with { KeyValue = null },
        };
    }
}
