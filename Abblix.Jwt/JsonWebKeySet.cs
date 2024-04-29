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

namespace Abblix.Jwt;

/// <summary>
/// Represents a JSON Web Key Set (JWKS) as defined by the JSON Web Key (JWK) specifications.
/// A JWKS is a set of keys containing the public keys used to verify any JSON Web Token (JWT) issued by the authorization server.
/// </summary>
public record JsonWebKeySet(JsonWebKey[] Keys)
{
    /// <summary>
    /// Gets an array of <see cref="JsonWebKey"/> objects representing the cryptographic keys.
    /// </summary>
    /// <remarks>
    /// The 'keys' property in a JWKS is an array of JWK objects. Each JWK object within the array is a JSON object representing a single public key.
    /// </remarks>
    [JsonPropertyName("keys")] public JsonWebKey[] Keys { get; init; } = Keys;
}
