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
/// Reads and writes a <see cref="JsonWebKeySet"/> with the options of the keys it holds, so its <c>keys</c> member is
/// matched exactly whatever options the caller serializes the set under.
/// </summary>
public sealed class JsonWebKeySetConverter : JsonConverter<JsonWebKeySet>
{
    /// <inheritdoc />
    /// <remarks>
    /// A set without a <c>keys</c> member holds no keys, as its type says, rather than a null array a caller would
    /// enumerate.
    /// </remarks>
    public override JsonWebKeySet? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        using var document = JsonDocument.ParseValue(ref reader);
        JsonMemberNames.RefuseRepeated(document.RootElement, "key set");

        // An object never deserializes to null, and a JSON null never reaches a converter
        var keySet = document.RootElement.Deserialize<KeySetDocument>(JsonWebKeySerializerOptions.Instance)!;
        return new JsonWebKeySet(keySet.Keys ?? []);
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, JsonWebKeySet value, JsonSerializerOptions options)
        => JsonSerializer.Serialize(writer, new KeySetDocument(value.Keys), JsonWebKeySerializerOptions.Instance);

    /// <summary>
    /// The set's members as JSON carries them: a type without this converter, so reading it does not call back in.
    /// </summary>
    private sealed record KeySetDocument([property: JsonPropertyName(JsonWebKeySet.KeysMember)] JsonWebKey[]? Keys);
}
