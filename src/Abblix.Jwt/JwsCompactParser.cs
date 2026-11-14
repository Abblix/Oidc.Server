// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The first link of the JWS validation chain: reads the header and the payload of a compact JWS into a token.
/// </summary>
internal static class JwsCompactParser
{
    /// <summary>
    /// Parses JWS string parts into header, payload, and signature.
    /// </summary>
    public static Result<JsonWebToken, JwtValidationError> Parse(string[] jwtParts)
    {
        byte[] headerPart, payloadPart;
        try
        {
            headerPart = Base64Url.DecodeFromChars(jwtParts[0]);
            payloadPart = Base64Url.DecodeFromChars(jwtParts[1]);
        }
        catch
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWT format: base64url decoding failed");
        }

        if (!TryParseJsonObject(headerPart, out var headerObject))
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWS header: must be a JSON object");
        }

        if (!TryParseJsonObject(payloadPart, out var payloadObject))
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWS payload: must be a JSON object");
        }

        var token = new JsonWebToken
        {
            Header = new (headerObject),
            Payload = new (payloadObject),
        };

        return token;
    }

    private static bool TryParseJsonObject(byte[] jwtPart, [NotNullWhen(true)] out JsonObject? jsonObject)
    {
        try
        {
            var json = Encoding.UTF8.GetString(jwtPart);
            jsonObject = JsonNode.Parse(json, documentOptions: RejectRepeatedMemberNames) as JsonObject;
        }
        catch (JsonException)
        {
            jsonObject = null;
        }
        return jsonObject is not null;
    }

    /// <summary>
    /// Makes the parser itself reject a repeated member name, which is the first of the two options
    /// RFC 7519 Section 4 and RFC 7515 Section 4 allow a recipient. It reports the repetition as a
    /// <see cref="JsonException"/> at parse time, alongside every other malformed-JSON verdict.
    /// </summary>
    private static readonly JsonDocumentOptions RejectRepeatedMemberNames = new()
    {
        AllowDuplicateProperties = false,
    };
}
