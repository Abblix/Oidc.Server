// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The link of the JWT validation chain that holds the <c>typ</c> header to the types the caller accepts.
/// </summary>
internal static class JwtTypeValidator
{
    /// <summary>
    /// Pins the JWT's <c>typ</c> header (RFC 7515 section 4.1.9) to the types the caller accepts, per
    /// the RFC 8725 section 3.11 token-type confusion guidance, as <see cref="ValidationParameters.TokenTypes"/>
    /// states them.
    /// </summary>
    /// <remarks>
    /// Matching is case-insensitive, and the <c>application/</c> prefix is stripped from the
    /// expectation as well as from the token, so either form may be written on either side.
    /// A <c>typ</c> is a media type: RFC 7515 section 4.1.9 says "Per RFC 2045, all media type values,
    /// subtype values, and parameter names are case insensitive", and RFC 2045 section 5.1 puts it
    /// flatly - "Matching of media type and subtype is ALWAYS case-insensitive". The same
    /// section 4.1.9 requires a recipient to treat a value without a '/' as if <c>application/</c>
    /// were prepended, which makes the short and long forms one name rather than two.
    /// Note that RFC 7515 section 5.3 does NOT apply here despite defining the library's general
    /// string-comparison rules: it ends by exempting exactly this parameter, "Only the 'typ'
    /// and 'cty' member values defined in this specification do not use these comparison
    /// rules".
    /// Folding costs no separation between the classes actually pinned here (<c>dpop+jwt</c>,
    /// <c>at+jwt</c>, <c>logout+jwt</c>): they differ in their letters, not
    /// their casing. The one place RFC 2045 keeps case significant is the value of a
    /// <c>;parameter=</c> tail, which no <c>typ</c> in these specifications carries; should one
    /// ever appear, this whole-string fold would be more permissive than the RFC on that tail.
    /// </remarks>
    public static Result<JsonWebToken, JwtValidationError> Validate(
        JsonWebToken token, ValidationParameters parameters)
    {
        var policy = parameters.TokenTypes;
        var typ = token.Header.Type;
        return policy.Rule switch
        {
            TokenTypeRule.CheckedByCaller => token,
            TokenTypeRule.OrUntyped when typ is null => token,
            TokenTypeRule.Exactly when typ is null => new JwtValidationError(
                JwtError.InvalidTokenType,
                $"JWT 'typ' header is missing - expected one of: {string.Join(", ", policy.Types)}"),
            TokenTypeRule.Exactly or TokenTypeRule.OrUntyped =>
                policy.Types.Any(expected => JwtTypeName.Matches(typ, expected))
                    ? token
                    : new JwtValidationError(
                        JwtError.InvalidTokenType,
                        $"JWT 'typ' header '{typ}' does not match expected token type(s): " +
                        string.Join(", ", policy.Types)),
            _ => throw new InvalidOperationException(
                $"Unknown {nameof(TokenTypeRule)} value {policy.Rule}."),
        };
    }
}
