// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
            headerPart = JoseBase64Url.Decode(jwtParts[0]);
            payloadPart = JoseBase64Url.Decode(jwtParts[1]);
        }
        catch
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWT format: base64url decoding failed");
        }

        if (!JoseJson.TryParseObject(headerPart, out var headerObject))
        {
            return new JwtValidationError(
                JwtError.MalformedToken,
                "Invalid JWS header: must be a JSON object");
        }

        if (!JoseJson.TryParseObject(payloadPart, out var payloadObject))
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
}
