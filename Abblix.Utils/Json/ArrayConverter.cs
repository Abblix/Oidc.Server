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
/// A custom JSON converter that handles the serialization and deserialization of arrays of a specific type.
/// Utilizes a specified element converter for individual elements of the array.
/// </summary>
/// <typeparam name="TElement">The type of the elements in the array.</typeparam>
/// <typeparam name="TConverter">The type of the converter used for the elements in the array.</typeparam>
public class ArrayConverter<TElement, TConverter> : JsonConverter<TElement[]?>
    where TConverter: JsonConverter<TElement>, new()
{
    private readonly TConverter _elementConverter = new();

    /// <summary>
    /// Reads and converts the JSON to an array of type <typeparamref name="TElement"/>.
    /// </summary>
    /// <param name="reader">The reader to read JSON from.</param>
    /// <param name="typeToConvert">The type of object to convert to.</param>
    /// <param name="options">Options for the serializer.</param>
    /// <returns>An array of <typeparamref name="TElement"/> or null if the JSON token is null.</returns>
    public override TElement[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                reader.Read();
                return null;

            case JsonTokenType.StartArray:
                break;

            default:
                throw new JsonException();
        }

        var result = new List<TElement>();
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.String:
                    var element = _elementConverter.Read(ref reader, typeof(TElement), options);
                    if (element != null)
                        result.Add(element);
                    break;

                case JsonTokenType.EndArray:
                    return result.ToArray();

                default:
                    throw new JsonException();
            }
        }

        throw new JsonException();
    }

    /// <summary>
    /// Writes an array of <typeparamref name="TElement"/> to JSON.
    /// </summary>
    /// <param name="writer">The writer to write JSON to.</param>
    /// <param name="value">The array of <typeparamref name="TElement"/> to write.</param>
    /// <param name="options">Options for the serializer.</param>
    public override void Write(Utf8JsonWriter writer, TElement[]? value, JsonSerializerOptions options)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        writer.WriteStartArray();
        try
        {
            foreach (var element in value)
            {
                _elementConverter.Write(writer, element, options);
            }
        }
        finally
        {
            writer.WriteEndArray();
        }
    }
}