// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Reads the scheme of an <c>Authorization</c> header the way HTTP defines it.
/// </summary>
internal static class AuthenticationHeaderValueExtensions
{
    /// <summary>
    /// Whether the header names the given scheme.
    /// </summary>
    /// <remarks>
    /// RFC 9110 section 11.1 identifies an authentication scheme by a case-insensitive token, so <c>bearer</c>,
    /// <c>Bearer</c> and <c>BEARER</c> are one scheme and a client is free to send any of them.
    /// </remarks>
    /// <param name="header">The header, or null when the request carries none.</param>
    /// <param name="scheme">The scheme to look for.</param>
    public static bool HasScheme(this AuthenticationHeaderValue? header, string scheme)
        => string.Equals(header?.Scheme, scheme, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The credentials of a request that carries the Authorization field on exactly one line.
    /// </summary>
    /// <remarks>
    /// RFC 9110 section 11.6.2 defines the field as <c>Authorization = credentials</c>, which is not a list, so
    /// section 5.3 forbids a sender to generate it on more than one line, and lines that were sent cannot be joined
    /// into one value. More than one line therefore names no credentials here; the endpoint refuses such a request
    /// on its own terms.
    /// </remarks>
    /// <param name="lines">The field lines as received, or null when the request carries none.</param>
    /// <returns>The parsed credentials, or null for no line, more than one line, or a line that does not parse.</returns>
    public static AuthenticationHeaderValue? FromSingleLine(IReadOnlyList<string>? lines)
        => lines is [var line] && AuthenticationHeaderValue.TryParse(line, out var header) ? header : null;
}
