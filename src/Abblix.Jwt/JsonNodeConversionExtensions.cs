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
/// Converts between the mutable JSON nodes a token is built from and the read-only elements a model carries.
/// </summary>
public static class JsonNodeConversionExtensions
{
    /// <summary>
    /// A static <see cref="JsonElement"/> representing a null value in JSON.
    /// This is used as a default value when a null JSON node needs to be represented as a <see cref="JsonElement"/>.
    /// </summary>
    private static readonly JsonElement NullJsonElement = "null".ToJsonElement();

    /// <summary>
    /// Converts a JsonNode to a JsonElement.
    /// </summary>
    /// <param name="jsonNode">The JsonNode to convert.</param>
    /// <returns>The converted JsonElement.</returns>
    public static JsonElement ToJsonElement(this JsonNode? jsonNode)
    {
        return jsonNode == null ? NullJsonElement : jsonNode.ToJsonString().ToJsonElement();
    }

    /// <summary>
    /// Converts a JSON string to a <see cref="JsonElement"/>.
    /// </summary>
    /// <param name="jsonString">The JSON string to convert.</param>
    /// <returns>A <see cref="JsonElement"/> representing the parsed JSON structure.</returns>
    /// <exception cref="JsonException">
    /// Thrown when the JSON string is malformed and cannot be parsed.
    /// </exception>
    /// <remarks>
    /// This method is useful for converting a JSON string into a <see cref="JsonElement"/>,
    /// allowing for easy manipulation and traversal of the JSON structure.
    /// </remarks>
    private static JsonElement ToJsonElement(this string jsonString)
        => JsonDocument.Parse(jsonString).RootElement;

    /// <summary>
    /// Converts a JsonElement to a JsonNode, allowing for more dynamic manipulation of the JSON structure.
    /// </summary>
    /// <param name="jsonElement">The JsonElement to convert.</param>
    /// <returns>The converted JsonNode.</returns>
    /// <remarks>
    /// This method is useful when you need to convert from a structured JsonElement to a more flexible JsonNode.
    /// </remarks>
    public static JsonNode? ToJsonNode(this JsonElement jsonElement)
        => JsonNode.Parse(jsonElement.GetRawText());
}
