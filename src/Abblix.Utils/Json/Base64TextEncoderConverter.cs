// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Utils.Json;

/// <summary>
/// Converts a byte array to and from standard base64 (RFC 4648 section 4) with padding, the encoding RFC 7517
/// section 4.7 requires for the certificates of a JWK's <c>x5c</c>.
/// </summary>
/// <remarks>
/// It reads base64url as well. Keys stored before <c>x5c</c> was written in standard base64 carry it in
/// base64url, and refusing them would leave those keys unreadable.
/// </remarks>
public class Base64TextEncoderConverter : JsonConverter<byte[]?>
{
    /// <summary>Reads a base64 or base64url string.</summary>
    public override byte[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.TokenType switch
        {
            JsonTokenType.String => Decode(reader.GetString()!),
            JsonTokenType.Null => null,
            _ => throw new JsonException($"Invalid token type: {reader.TokenType}"),
        };

        static byte[] Decode(string value)
        {
            var standard = value.Replace('-', '+').Replace('_', '/');
            var padded = standard.PadRight(standard.Length + (4 - standard.Length % 4) % 4, '=');
            try
            {
                return Convert.FromBase64String(padded);
            }
            catch (FormatException ex)
            {
                throw new JsonException($"Invalid base64 encoding: {value}", ex);
            }
        }
    }

    /// <summary>Writes standard base64 with padding.</summary>
    public override void Write(Utf8JsonWriter writer, byte[]? value, JsonSerializerOptions options)
    {
        if (value == null)
            writer.WriteNullValue();
        else
            writer.WriteBase64StringValue(value);
    }
}
