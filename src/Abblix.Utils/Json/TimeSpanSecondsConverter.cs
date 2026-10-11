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
/// A custom JSON converter for TimeSpan objects that serializes and deserializes them as a number of seconds.
/// </summary>
public class TimeSpanSecondsConverter : JsonConverter<TimeSpan>
{
    /// <summary>
    /// Reads a JSON number representing the total seconds and converts it to a TimeSpan object.
    /// </summary>
    /// <param name="reader">The reader to read JSON data from.</param>
    /// <param name="typeToConvert">The type to convert; expected to be TimeSpan.</param>
    /// <param name="options">Options for the serializer.</param>
    /// <returns>A TimeSpan object representing the value read from the JSON.</returns>
    public override TimeSpan Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var seconds = reader.TokenType switch
        {
            JsonTokenType.String when long.TryParse(reader.GetString(), out var parsed) => parsed,
            JsonTokenType.Number when reader.TryGetInt64(out var number) => number,
            _ => throw new JsonException(),
        };

        // A duration is never negative, and one past what a TimeSpan holds is a malformed value like any other,
        // so both are refused as such rather than surfacing as an overflow from the conversion
        if (seconds < 0 || seconds > (long)TimeSpan.MaxValue.TotalSeconds)
            throw new JsonException($"{seconds} is not a number of seconds a duration can have");

        return TimeSpan.FromSeconds(seconds);
    }

    /// <summary>
    /// Writes a TimeSpan object to JSON as a number representing its total seconds.
    /// </summary>
    /// <param name="writer">The writer to write JSON data to.</param>
    /// <param name="value">The TimeSpan value to write.</param>
    /// <param name="options">Options for the serializer.</param>
    public override void Write(Utf8JsonWriter writer, TimeSpan value, JsonSerializerOptions options)
        => writer.WriteNumberValue((long)value.TotalSeconds);
}
