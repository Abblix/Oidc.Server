// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;

namespace Abblix.Jwt;

/// <summary>
/// Reads one JSON Web Key object off the reader as the subtype its key type names.
/// </summary>
internal static class JsonWebKeyDocument
{
    /// <summary>The key the object on <paramref name="reader"/> holds, as the subtype its <c>kty</c> names.</summary>
    /// <exception cref="JsonException">The value is not an object, names a member twice, its <c>kty</c> is missing
    /// or empty or not one of the three, or a member does not read.</exception>
    public static JsonWebKey? Read(ref Utf8JsonReader reader, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected StartObject token");
        }

        var root = JsonElement.ParseValue(ref reader);

        JsonMemberNames.RefuseRepeated(root, "key");

        if (!root.TryGetProperty(JsonWebKeyPropertyNames.KeyType, out var ktyElement))
        {
            throw new JsonException($"Missing required '{JsonWebKeyPropertyNames.KeyType}' property");
        }

        var kty = ktyElement.GetString();
        if (string.IsNullOrEmpty(kty))
        {
            throw new JsonException($"'{JsonWebKeyPropertyNames.KeyType}' property cannot be null or empty");
        }

        return JsonWebKeySubtypes.Deserialize(kty, root, options);
    }
}
