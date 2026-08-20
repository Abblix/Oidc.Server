// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils.Json;

using System;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Reads and writes a JSON value that may be either a single element of <typeparamref name="T"/> or an array of
/// such elements, exposing it uniformly to .NET as <c>T[]</c>. On write, a single-element array is emitted as a bare
/// scalar (not an array), matching the OAuth 2.0 / OpenID Connect convention used for parameters such as
/// <c>aud</c> and <c>response_type</c>.
/// </summary>
/// <typeparam name="T">The element type. A converter for <typeparamref name="T"/> must be available in the
/// serializer options.</typeparam>
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
                return [ReadFrom(ref reader, elementType, converter, options)];

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
                // Return on EndArray rather than break: a bare break exits only the switch, so the
                // enclosing while would then read the token AFTER the array. When the array is a
                // property value inside an object that next token is EndObject (or the next property
                // name), which the default case rejects - corrupting deserialization of any
                // single-or-array value that appears as an array (e.g. a multi-valued "resource").
                case JsonTokenType.EndArray:
                    return values.ToArray();

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
