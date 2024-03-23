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
