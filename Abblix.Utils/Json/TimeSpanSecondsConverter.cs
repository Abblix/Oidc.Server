// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
