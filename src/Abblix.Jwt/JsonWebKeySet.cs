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
[JsonConverter(typeof(JsonWebKeySetConverter))]
public sealed record JsonWebKeySet(JsonWebKey[] Keys)
{
    /// <summary>The JSON member a JWK Set holds its keys in (RFC 7517 section 5.1).</summary>
    internal const string KeysMember = "keys";

    /// <summary>
    /// The keys belonging to this JWK Set. Serialized to the JSON "keys" member by
    /// <see cref="JsonWebKeySetConverter"/>.
    /// Each entry is a polymorphic <see cref="JsonWebKey"/> resolved by its "kty" parameter.
    /// </summary>
    /// <remarks>
    /// The member name is stated here as well for the readers that describe the type from its properties rather than
    /// through the converter, such as an OpenAPI schema generator, so a host keeping its own naming policy still
    /// publishes a schema with the name the converter reads.
    /// </remarks>
    [JsonPropertyName(KeysMember)]
    public JsonWebKey[] Keys { get; init; } = Keys;
}
