// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
