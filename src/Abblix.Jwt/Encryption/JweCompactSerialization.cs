// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The JWE Compact Serialization (RFC 7516 section 7.1), shared by the side that writes a JWE and the side that
/// reads one: five base64url parts joined by dots, the first of them the protected header the content encryption
/// authenticates.
/// </summary>
internal static class JweCompactSerialization
{
    /// <summary>
    /// Encodes a JSON object to base64url string for JWT usage.
    /// </summary>
    public static string EncodeHeader(JsonObject json)
    {
        var options = new JsonSerializerOptions { WriteIndented = false };
        var bytes = Encoding.UTF8.GetBytes(json.ToJsonString(options));
        return Base64Url.EncodeToString(bytes);
    }

    /// <summary>
    /// Encodes JWE parts into compact serialization format.
    /// </summary>
    public static string Encode(string encodedHeader, params byte[][] parts)
    {
        return string.Join(".", parts
            .Select(p => Base64Url.EncodeToString(p))
            .Prepend(encodedHeader));
    }

    /// <summary>
    /// The Additional Authenticated Data of the content encryption: the protected header as it is sent
    /// (RFC 7516 section 5.1, step 14).
    /// </summary>
    public static byte[] AdditionalAuthenticatedData(string encodedHeader) => Encoding.ASCII.GetBytes(encodedHeader);

    /// <summary>
    /// Decodes every part of a compact serialization.
    /// </summary>
    public static Result<byte[][], JwtValidationError> Decode(string[] jwtParts)
    {
        // Invalid base64 means invalid token
        try
        {
            return Array.ConvertAll(jwtParts, static s => Base64Url.DecodeFromChars(s));
        }
        catch (FormatException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid base64url encoding in JWE");
        }
    }
}
