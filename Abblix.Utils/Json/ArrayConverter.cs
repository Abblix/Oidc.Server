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
/// JSON converter for nullable-element arrays of <typeparamref name="TElement"/>. Each non-null element is
/// delegated to an instance of <typeparamref name="TConverter"/>; each <c>null</c> element is preserved as
/// <c>default(<typeparamref name="TElement"/>)</c> on read and emitted as a JSON <c>null</c> on write,
/// independently of how the inner converter would handle null. A whole-array JSON <c>null</c> deserializes
/// to a <c>null</c> array. Read accepts any JSON value form the inner converter can consume (string, number,
/// boolean, object, nested array), keeping it symmetric with whatever Write can produce.
/// </summary>
/// <typeparam name="TElement">The element type of the array.</typeparam>
/// <typeparam name="TConverter">The per-element converter; instantiated once per <see cref="ArrayConverter{TElement,TConverter}"/>.</typeparam>
public class ArrayConverter<TElement, TConverter> : JsonConverter<TElement?[]?>
    where TConverter: JsonConverter<TElement>, new()
{
    private readonly TConverter _elementConverter = new();

    /// <summary>
    /// Deserializes a JSON array into <typeparamref name="TElement"/>?[]?, or returns a <c>null</c> array
    /// when the whole value is JSON <c>null</c>. Inside the array, a JSON <c>null</c> element becomes
    /// <c>default(<typeparamref name="TElement"/>)</c> without invoking the inner converter; every other
    /// value-start token (string, number, boolean, object, nested array) is forwarded to the inner converter.
    /// </summary>
    /// <param name="reader">The reader positioned at the value to deserialize.</param>
    /// <param name="typeToConvert">The CLR type the framework asked to deserialize into.</param>
    /// <param name="options">Serializer options forwarded to the inner converter.</param>
    /// <returns>The deserialized array, or <c>null</c>.</returns>
    public override TElement?[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
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

        var result = new List<TElement?>();
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.Null:
                    result.Add(default);
                    break;

                case JsonTokenType.String:
                case JsonTokenType.Number:
                case JsonTokenType.True:
                case JsonTokenType.False:
                case JsonTokenType.StartObject:
                case JsonTokenType.StartArray:
                    var element = _elementConverter.Read(ref reader, typeof(TElement), options);
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
    public override void Write(Utf8JsonWriter writer, TElement?[]? value, JsonSerializerOptions options)
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
                if (element is null)
                {
                    writer.WriteNullValue();
                }
                else
                {
                    _elementConverter.Write(writer, element, options);
                }
            }
        }
        finally
        {
            writer.WriteEndArray();
        }
    }
}
