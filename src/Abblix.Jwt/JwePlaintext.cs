// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Text;
using Abblix.Jwt.Encryption;

namespace Abblix.Jwt;

/// <summary>
/// Tells what the plaintext of a JWE is: RFC 7519 section 7.2 step 8 has a plaintext under cty JWT "a JWT that was the
/// subject of nested signing or encryption operations", and steps 9 and 10 any other the claims set, "a completely
/// valid JSON object".
/// </summary>
internal static class JwePlaintext
{
    /// <summary>
    /// Whether <paramref name="plaintext"/> is the claims set of the JWE <paramref name="jwtParts"/>, and the token it
    /// makes with the JWE's header. A plaintext that is not a JSON object is taken as a nested JWT, as a token issued
    /// before cty was written carries one without it.
    /// </summary>
    /// <param name="jwtParts">The compact parts of the JWE the plaintext came from.</param>
    /// <param name="plaintext">The decrypted plaintext.</param>
    /// <param name="claimsSet">The token the claims set makes, where it is one.</param>
    /// <param name="nestedJwt">The nested JWT as UTF-8 text, where the plaintext is one.</param>
    public static bool TryReadClaimsSet(
        string[] jwtParts,
        byte[] plaintext,
        [NotNullWhen(true)] out JsonWebToken? claimsSet,
        [NotNullWhen(false)] out string? nestedJwt)
    {
        // Section 5.2: "While media type names are not case sensitive", so cty is compared in one case
        if (!JweEnvelope.Read(jwtParts).TryGetSuccess(out var envelope) ||
            envelope.Header.ContentType?.ToUpperInvariant() == JsonWebTokenTypes.Jwt ||
            !JoseJson.TryParseObject(plaintext, out var claims))
        {
            claimsSet = null;
            nestedJwt = Encoding.UTF8.GetString(plaintext);
            return false;
        }

        claimsSet = new JsonWebToken { Header = envelope.Header, Payload = new JsonWebTokenPayload(claims) };
        nestedJwt = null;
        return true;
    }
}
