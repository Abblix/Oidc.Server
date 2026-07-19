// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
// 
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
// 
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
// 
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
// 
// For full licensing terms, please visit:
// 
// https://oidc.abblix.com/license
// 
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
        return TimeSpan.FromSeconds(
            reader.TokenType switch
            {
                JsonTokenType.String when long.TryParse(reader.GetString(), out var parsed) => parsed,
                JsonTokenType.Number => reader.GetInt64(),
                _ => throw new JsonException(),
            });
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
