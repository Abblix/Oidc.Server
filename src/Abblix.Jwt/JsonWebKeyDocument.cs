// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;

namespace Abblix.Jwt;

/// <summary>
/// Reads one JSON Web Key object off the reader: its key type, which decides the subtype, and the object itself
/// for that subtype to read.
/// </summary>
internal static class JsonWebKeyDocument
{
    /// <summary>The key's <c>kty</c> and the raw JSON of the whole object.</summary>
    /// <exception cref="JsonException">The value is not an object, names a member twice, or its <c>kty</c> is missing
    /// or empty.</exception>
    public static (string KeyType, string Json) Read(ref Utf8JsonReader reader)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Expected StartObject token");
        }

        using var document = JsonDocument.ParseValue(ref reader);
        var root = document.RootElement;

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

        return (kty, root.GetRawText());
    }
}
