// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Reads and writes the JOSE header parameters that hold an array of strings or a JWK, telling a malformed
/// parameter apart from an absent one.
/// </summary>
internal static class JsonHeaderParameters
{
    /// <summary>
    /// Reads a header parameter holding an array of strings: true with <c>null</c> when it is absent, false when it
    /// is present in another shape.
    /// </summary>
    public static bool TryReadStrings(JsonObject json, string name, out IReadOnlyList<string>? strings)
    {
        strings = null;
        if (!json.TryGetPropertyValue(name, out var node) || node is null)
            return true;
        if (node is not JsonArray array)
            return false;

        var result = new string[array.Count];
        for (var i = 0; i < array.Count; i++)
        {
            if (array[i] is not JsonValue value || !value.TryGetValue<string>(out var item))
                return false;
            result[i] = item;
        }

        strings = result;
        return true;
    }

    /// <summary>Writes a header parameter holding an array of strings, or removes it when the array is null.</summary>
    public static void SetStrings(JsonObject json, string name, IReadOnlyList<string>? strings)
    {
        if (strings is null)
        {
            json.Remove(name);
            return;
        }

        var array = new JsonArray();
        foreach (var item in strings)
            array.Add(item);
        json[name] = array;
    }

    /// <summary>
    /// Reads a header parameter holding a JWK: true with <c>null</c> when it is absent, false when it is not an
    /// object or is an object that is not a valid JWK.
    /// </summary>
    public static bool TryReadKey(JsonObject json, string name, out JsonWebKey? key)
    {
        key = null;
        if (!json.TryGetPropertyValue(name, out var node) || node is null)
            return true;
        if (node is not JsonObject obj)
            return false;

        try
        {
            key = obj.Deserialize<JsonWebKey>();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>Writes a header parameter holding a JWK, or removes it when the key is null.</summary>
    public static void SetKey(JsonObject json, string name, JsonWebKey? key)
    {
        if (key is not null)
            json[name] = JsonSerializer.SerializeToNode(key);
        else
            json.Remove(name);
    }

}
