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
    public override JsonWebKeySet? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => JsonSerializer.Deserialize<KeySetDocument>(ref reader, JsonWebKeySerializerOptions.Instance) is { } document
            ? new JsonWebKeySet(document.Keys!)
            : null;

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, JsonWebKeySet value, JsonSerializerOptions options)
        => JsonSerializer.Serialize(writer, new KeySetDocument(value.Keys), JsonWebKeySerializerOptions.Instance);

    /// <summary>
    /// The set's members as JSON carries them: a type without this converter, so reading it does not call back in.
    /// </summary>
    private sealed record KeySetDocument([property: JsonPropertyName("keys")] JsonWebKey[]? Keys);
}
