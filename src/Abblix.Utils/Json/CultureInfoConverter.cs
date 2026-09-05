// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Utils.Json;

/// <summary>
/// A custom JSON converter for <see cref="CultureInfo"/> objects.
/// It allows for the serialization and deserialization of <see cref="CultureInfo"/> instances
/// when working with JSON data.
/// </summary>
public class CultureInfoConverter : JsonConverter<CultureInfo>
{
    /// <summary>
    /// Reads and converts the JSON to a <see cref="CultureInfo"/>.
    /// </summary>
    /// <param name="reader">The reader to read the JSON from.</param>
    /// <param name="typeToConvert">The type of object to convert to.</param>
    /// <param name="options">The serializer options to use.</param>
    /// <returns>The deserialized <see cref="CultureInfo"/> object.</returns>
    /// <exception cref="JsonException">
    /// Thrown when the JSON token is not a string or null, or if the string is not a valid culture identifier.
    /// </exception>
    public override CultureInfo Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.TokenType switch
        {
            JsonTokenType.Null => CultureInfo.InvariantCulture,
            JsonTokenType.String => new CultureInfo(reader.GetString().NotNull("reader.GetString() != null")),
            _ => throw new JsonException(),
        };
    }

    /// <summary>
    /// Writes a specified <see cref="CultureInfo"/> object as JSON.
    /// </summary>
    /// <param name="writer">The writer to write the JSON to.</param>
    /// <param name="value">The <see cref="CultureInfo"/> value to convert.</param>
    /// <param name="options">The serializer options to use.</param>
    /// <remarks>
    /// If the <see cref="CultureInfo"/> is <see cref="CultureInfo.InvariantCulture"/>,
    /// it writes a null value; otherwise, it writes the culture name as a string.
    /// </remarks>
    public override void Write(Utf8JsonWriter writer, CultureInfo value, JsonSerializerOptions options)
    {
        if (ReferenceEquals(value, CultureInfo.InvariantCulture))
            writer.WriteNullValue();
        else
            writer.WriteStringValue(value.Name);
    }
}
