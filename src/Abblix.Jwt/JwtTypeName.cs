// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// Compares JWT <c>typ</c> header values, which name a media type and therefore have more than one spelling
/// for the same value.
/// </summary>
/// <remarks>
/// Two rules make the spellings equivalent. RFC 7515 Section 4.1.9: "A recipient using the media type value
/// MUST treat it as if 'application/' were prepended to any 'typ' value not containing a '/'", so
/// <c>at+jwt</c> and <c>application/at+jwt</c> are one name. RFC 2045 Section 5.1: "Matching of media type and
/// subtype is ALWAYS case-insensitive", so casing carries no meaning either.
/// Note that RFC 7515 Section 5.3, which defines this library's general string-comparison rules, does not
/// apply: it ends by exempting exactly this parameter, "Only the 'typ' and 'cty' member values defined in this
/// specification do not use these comparison rules".
/// This lives here rather than beside each comparison so the rule has one implementation: a second copy would
/// be a second, quietly different answer to "is this an access token".
/// </remarks>
public static class JwtTypeName
{
    private const string ApplicationPrefix = "application/";

    /// <summary>
    /// Determines whether two <c>typ</c> values name the same token type, in any spelling of either.
    /// </summary>
    /// <param name="actual">The value read from the token's header, or <c>null</c> when it carries none.</param>
    /// <param name="expected">The value the caller expects, written in whichever spelling it prefers.</param>
    /// <returns><c>true</c> when both name the same media type.</returns>
    public static bool Matches(string? actual, string expected)
        => actual is not null && string.Equals(
            StripApplicationPrefix(actual),
            StripApplicationPrefix(expected),
            StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Removes the <c>application/</c> prefix when present, reaching RFC 7515 Section 4.1.9's equivalence from
    /// either form rather than only from the short one.
    /// </summary>
    /// <param name="typ">The <c>typ</c> value to normalise.</param>
    /// <returns>The value without its media-type prefix.</returns>
    /// <remarks>
    /// The prefix match ignores case because it is the media type portion, which RFC 2045 Section 5.1 declares
    /// case-insensitive; matching it ordinally would leave <c>Application/at+jwt</c> unstripped and therefore
    /// unmatchable.
    /// </remarks>
    public static string StripApplicationPrefix(string typ)
        => typ.StartsWith(ApplicationPrefix, StringComparison.OrdinalIgnoreCase)
            ? typ[ApplicationPrefix.Length..]
            : typ;
}
