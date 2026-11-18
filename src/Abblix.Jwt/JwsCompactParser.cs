// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Reads the header and the payload of a compact JWS into a token, as RFC 7515 section 5.2 has a recipient decode and
/// parse them, and verifies nothing: the first link of the JWS validation chain, and the one reading a consumer that
/// judges a token's claims before its signature starts from.
/// </summary>
public static class JwsCompactParser
{
    /// <summary>
    /// The token the first two of <paramref name="jwtParts"/> (header and payload) hold, or
    /// <see cref="JwtError.MalformedToken"/> when either is not strict base64url of a JSON object in UTF-8 without a
    /// repeated member name.
    /// </summary>
    /// <param name="jwtParts">The dot-separated parts of a compact JWS.</param>
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
