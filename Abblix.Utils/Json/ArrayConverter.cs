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
