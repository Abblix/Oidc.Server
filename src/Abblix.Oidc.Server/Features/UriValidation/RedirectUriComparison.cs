// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers;

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// How one redirect URI is compared with another, at the authorization endpoint against the registered ones and at the
/// token endpoint against the one the authorization request named.
/// </summary>
/// <remarks>
/// RFC 9700 section 4.1.3: "the authorization server MUST ensure that the two URIs are equal; see Section 6.2.1 of
/// [RFC3986], Simple String Comparison", and RFC 6749 section 4.1.3 has the two values at the token endpoint
/// "identical". So the URIs are compared as written, character for character: two spellings RFC 3986 normalizes to one
/// URI (host case, a default port, an encoded unreserved character) are different redirect URIs.
/// </remarks>
internal static class RedirectUriComparison
{
    /// <summary>
    /// Whether two redirect URIs are written alike, or both absent.
    /// </summary>
    public static bool AreIdentical(Uri? first, Uri? second)
        => string.Equals(first?.OriginalString, second?.OriginalString, StringComparison.Ordinal);

    /// <summary>
    /// Whether two loopback redirect URIs are written alike but for their ports, the one exception RFC 9700 section
    /// 4.1.3 makes: "the authorization server MUST allow variable port numbers as described in Section 7.3 of
    /// [RFC8252]".
    /// </summary>
    public static bool AreIdenticalButPort(Uri registered, Uri requested)
        => string.Equals(WithoutPort(registered.OriginalString), WithoutPort(requested.OriginalString),
            StringComparison.Ordinal);

    /// <summary>
    /// The URI as written, with the port of its authority left out.
    /// </summary>
    private static string WithoutPort(string uri)
    {
        var authorityStart = uri.IndexOf(Uri.SchemeDelimiter, StringComparison.Ordinal);
        if (authorityStart < 0)
            return uri;

        authorityStart += Uri.SchemeDelimiter.Length;
        var authorityEnd = uri.IndexOfAny(AuthorityEnds, authorityStart);
        if (authorityEnd < 0)
            authorityEnd = uri.Length;

        // The last colon of the authority starts its port when only digits follow it, which also leaves the colons of an
        // IPv6 literal's brackets and of user information where they are
        var portStart = uri.LastIndexOf(':', authorityEnd - 1, authorityEnd - authorityStart);
        if (portStart < 0 || uri.AsSpan(portStart + 1, authorityEnd - portStart - 1).ContainsAnyExcept(Digits))
            return uri;

        return string.Concat(uri.AsSpan(0, portStart), uri.AsSpan(authorityEnd));
    }

    private static readonly char[] AuthorityEnds = ['/', '?', '#'];

    private static readonly SearchValues<char> Digits = SearchValues.Create("0123456789");
}
