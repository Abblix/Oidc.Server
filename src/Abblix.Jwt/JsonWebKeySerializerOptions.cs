// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Jwt;

/// <summary>
/// The options a key and a key set are read and written with, whatever options the caller serializes them under.
/// </summary>
/// <remarks>
/// A key is a protocol object other parties read member by member, so nothing the host chose for its own payloads
/// reaches it: no converter of the host's, which would rewrite <c>kty</c> or <c>kid</c>, and no case-insensitive
/// matching, which would read <c>KID</c> as <c>kid</c> here and not at a peer. Each member carries its own name, so
/// no naming policy applies either, and indentation is the writer's.
/// </remarks>
internal static class JsonWebKeySerializerOptions
{
    /// <summary>
    /// Member names matched exactly, unknown members ignored and absent members omitted. A member named twice is
    /// refused before these options are reached (<see cref="JsonMemberNames"/>).
    /// </summary>
    public static JsonSerializerOptions Instance { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            // A JWK omits an absent member rather than serializing it as null (RFC 7517): a public-only key
            // carries no private-key parameters, so the JWKS must not emit "d": null etc.
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
