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
/// A JWK Set's members as JSON carries them: a type without the set's converter, so reading it does not call back
/// in, read and written with the options of the keys it holds.
/// </summary>
/// <param name="Keys">The set's keys, or null when the set has no keys member.</param>
internal sealed record JsonWebKeySetDocument([property: JsonPropertyName(JsonWebKeySet.KeysMember)] JsonWebKey[]? Keys)
{
    /// <summary>
    /// Reads the set an object holds. A set without a <c>keys</c> member holds no keys, as its type says, rather than
    /// a null array a caller would enumerate.
    /// </summary>
    /// <param name="value">An object: the converter is its only caller, and a JSON null never reaches a converter.
    /// </param>
    public static JsonWebKeySet Read(JsonElement value)
    {
        // An object never deserializes to null, and a JSON null never reaches the converter that calls this
        var document = value.Deserialize<JsonWebKeySetDocument>(JsonWebKeySerializerOptions.Instance)!;
        return new JsonWebKeySet(document.Keys ?? []);
    }

    /// <summary>
    /// Writes <paramref name="value"/> with its <c>keys</c> member.
    /// </summary>
    public static void Write(Utf8JsonWriter writer, JsonWebKeySet value)
        => JsonSerializer.Serialize(
            writer,
            new JsonWebKeySetDocument(value.Keys),
            JsonWebKeySerializerOptions.Instance);
}
