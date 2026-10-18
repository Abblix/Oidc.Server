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
/// The options a key's concrete subtype is serialized with: the host's naming and formatting, with absent members
/// always omitted.
/// </summary>
internal static class JsonWebKeySerializerOptions
{
    /// <summary>
    /// A copy of the host's options that omits absent members whatever the host chose.
    /// </summary>
    public static JsonSerializerOptions For(JsonSerializerOptions options)
    {
        var result = new JsonSerializerOptions
        {
            // A JWK omits an absent member rather than serializing it as null (RFC 7517): a public-only key
            // carries no private-key parameters, so the JWKS must not emit "d": null etc. This is forced here,
            // independent of the host's options, because it is a property of JWK serialization itself.
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = options.PropertyNamingPolicy,
            WriteIndented = options.WriteIndented,
            PropertyNameCaseInsensitive = options.PropertyNameCaseInsensitive,
        };

        foreach (var converter in options.Converters)
            result.Converters.Add(converter);

        return result;
    }
}
