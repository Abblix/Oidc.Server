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
}
