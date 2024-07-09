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

namespace Abblix.Utils.Json;

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// A JSON converter that handles deserialization and serialization of a JSON value
/// that could either be a single string or an array of strings.
/// </summary>
public class SingleOrArrayConverter<T> : JsonConverter<T[]>
{
    /// <summary>
    /// Reads and converts the JSON to a string array.
    /// If the JSON token is a single string, it returns an array containing one element.
    /// If it is an array of strings, it converts each element and returns them in an array.
    /// </summary>
    /// <param name="reader">The reader from which to read the JSON document.</param>
    /// <param name="typeToConvert">The type to convert. Expected to be a string array.</param>
    /// <param name="options">Options for the serializer.</param>
    /// <returns>An array of strings parsed from the JSON input.</returns>
    /// <exception cref="JsonException">Thrown if an unexpected token type is encountered.</exception>

    public override T[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var elementType = typeof(T);
        var converter = (JsonConverter<T>)options.GetConverter(elementType)
                        ?? throw new JsonException($"No converter found for {elementType}");

        switch (reader.TokenType)
        {
            case JsonTokenType.Null:
                return null;

            case JsonTokenType.String:
                return new[] { ReadFrom(ref reader, elementType, converter, options) };

            case JsonTokenType.StartArray:
                break;

            default:
                throw new JsonException("Unexpected token type.");
        }

        var values = new List<T>();
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.EndArray:
                    break;

                case JsonTokenType.String:
                    values.Add(ReadFrom(ref reader, elementType, converter, options));
                    break;

                default:
                    throw new JsonException("Unexpected token type in array.");
            }
        }
        return values.ToArray();

        static T ReadFrom(ref Utf8JsonReader reader, Type elementType, JsonConverter<T> converter, JsonSerializerOptions options)
        {
            return converter.Read(ref reader, elementType, options)
                   ?? throw new JsonException("Null values are not allowed");
        }
    }

    /// <summary>
    /// Writes a string array to a JSON writer.
    /// If the array contains a single string, it writes it as a single string value.
    /// If it contains multiple strings, it writes them as an array of strings.
    /// </summary>
    /// <param name="writer">The writer to which the JSON will be written.</param>
    /// <param name="value">The string array to write.</param>
    /// <param name="options">Options for the serializer.</param>
    /// <exception cref="ArgumentNullException">Thrown if the writer or value is null.</exception>
    public override void Write(Utf8JsonWriter writer, T[]? value, JsonSerializerOptions options)
    {
        var elementType = typeof(T);
        var converter = (JsonConverter<T>)options.GetConverter(elementType)
                        ?? throw new JsonException($"No converter found for {elementType}");

        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        switch (value.Length)
        {
            case 1:
                converter.Write(writer, value[0], options);
                break;

            default:
                writer.WriteStartArray();
                foreach (var item in value)
                {
                    converter.Write(writer, item, options);
                }
                writer.WriteEndArray();
                break;
        }
    }
}
