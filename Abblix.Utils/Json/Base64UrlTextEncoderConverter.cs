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
/// A JSON converter for handling the serialization and deserialization of byte arrays as Base64 URL-encoded strings.
/// </summary>
public class Base64UrlTextEncoderConverter : JsonConverter<byte[]?>
{
    /// <summary>
    /// Reads and converts the JSON token to a byte array.
    /// </summary>
    /// <param name="reader">The reader to read the JSON token from.</param>
    /// <param name="typeToConvert">The type of object to convert.</param>
    /// <param name="options">Options for the serializer.</param>
    /// <returns>A byte array if the token is a string, otherwise null.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the token is not a string or null.</exception>
    public override byte[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.TokenType switch
        {
            JsonTokenType.String => HttpServerUtility.UrlTokenDecode(reader.GetString()!),
            JsonTokenType.Null => null,
            _ => throw new InvalidOperationException($"Invalid token type: {reader.TokenType}"),
        };
    }

    /// <summary>
    /// Writes a byte array as a Base64 URL-encoded string to the JSON writer.
    /// </summary>
    /// <param name="writer">The writer to write the JSON token to.</param>
    /// <param name="value">The byte array to write.</param>
    /// <param name="options">Options for the serializer.</param>
    public override void Write(Utf8JsonWriter writer, byte[]? value, JsonSerializerOptions options)
    {
        if (value != null)
            writer.WriteStringValue(HttpServerUtility.UrlTokenEncode(value));
        else
            writer.WriteNullValue();
    }
}
