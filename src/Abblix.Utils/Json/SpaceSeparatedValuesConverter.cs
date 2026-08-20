// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Utils.Json;

/// <summary>
/// A custom JSON converter that handles arrays of strings, converting them to and from space-separated values in JSON.
/// </summary>
public class SpaceSeparatedValuesConverter: JsonConverter<string[]>
{
    /// <summary>
    /// Reads a JSON string containing space-separated values and converts it to an array of strings.
    /// </summary>
    /// <param name="reader">The reader to read JSON from.</param>
    /// <param name="typeToConvert">The type of object to convert to. Expected to be an array of strings.</param>
    /// <param name="options">Options for the serializer.</param>
    /// <returns>An array of strings parsed from the space-separated values in the JSON string.</returns>
    public override string[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetString()?.Split(' ');

    /// <summary>
    /// Writes an array of strings to JSON as a single string with values separated by spaces.
    /// </summary>
    /// <param name="writer">The writer to write JSON to.</param>
    /// <param name="value">The array of strings to write.</param>
    /// <param name="options">Options for the serializer.</param>
    public override void Write(Utf8JsonWriter writer, string[] value, JsonSerializerOptions options)
        => writer.WriteStringValue(string.Join(' ', value));
}
