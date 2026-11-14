// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;

/// <summary>
/// The registered claims CIBA Core 1.0 section 7.1.1 requires of a signed authentication request: "The JWT MUST also
/// contain the following [RFC7519] registered claims", aud, iss, exp, iat, nbf and jti, with "The Audience claim MUST
/// contain the value of the Issuer Identifier for the OP".
/// </summary>
internal static class SignedAuthenticationRequestClaims
{
    /// <summary>
    /// The claims whose value is a string, which an empty one does not carry.
    /// </summary>
    private static readonly string[] Strings = [JwtClaimTypes.Issuer, JwtClaimTypes.JwtId];

    /// <summary>
    /// The claims whose value is a NumericDate (RFC 7519 section 2), which a null names no time with: an object with a
    /// null exp would never expire.
    /// </summary>
    private static readonly string[] NumericDates =
        [JwtClaimTypes.ExpiresAt, JwtClaimTypes.IssuedAt, JwtClaimTypes.NotBefore];

    /// <summary>
    /// Why the signed authentication request's claims fall short of section 7.1.1, or null when they do not.
    /// </summary>
    /// <param name="claims">The validated claims of the request object.</param>
    /// <param name="issuer">The issuer identifier of the tenant the request reached, compared as it is written, the
    /// way the request object's validator compares it.</param>
    public static string? WhyRefused(JsonObject claims, Uri issuer)
    {
        var missing =
            Strings.FirstOrDefault(claim => claims[claim] is not JsonValue value ||
                                            !value.TryGetValue<string>(out var text) || text.Length == 0) ??
            NumericDates.FirstOrDefault(claim => claims[claim]?.GetValueKind() != JsonValueKind.Number);

        if (missing != null)
            return $"The signed authentication request must carry the {missing} claim";

        return new JsonWebTokenPayload(claims).Audiences.Contains(issuer.OriginalString, StringComparer.Ordinal)
            ? null
            : "The signed authentication request must name the issuer identifier as its audience";
    }
}
