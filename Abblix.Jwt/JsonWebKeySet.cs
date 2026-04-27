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
/// A JSON Web Key Set (JWK Set) per RFC 7517 Section 5: a JSON document containing an array
/// of JSON Web Keys. Authorization servers publish their JWK Set at the <c>jwks_uri</c>
/// endpoint so that relying parties can discover the keys used to validate or encrypt tokens.
/// </summary>
public record JsonWebKeySet(JsonWebKey[] Keys)
{
    /// <summary>
    /// The keys belonging to this JWK Set. Serialized to the JSON "keys" member.
    /// Each entry is a polymorphic <see cref="JsonWebKey"/> resolved by its "kty" parameter.
    /// </summary>
    [JsonPropertyName("keys")] public JsonWebKey[] Keys { get; init; } = Keys;
}
