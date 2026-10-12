// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.Issuer;

/// <summary>
/// What an issuer this server declares must be, asked of the server's issuer and of every tenant's alike.
/// </summary>
/// <remarks>
/// An Issuer Identifier is "a case-sensitive URL using the "https" scheme that contains scheme, host, and optionally,
/// port number and path components and no query or fragment components" (OpenID Connect Core 1.0 section 1.2). The
/// scheme is checked by name because on Unix a bare path parses as an absolute file address.
/// </remarks>
internal static class IssuerIdentifier
{
    /// <summary>
    /// Why <paramref name="issuer"/> cannot be an issuer, or null when it can.
    /// </summary>
    /// <param name="issuer">The issuer as configured.</param>
    /// <param name="allowHttp">Whether an http issuer is let through, see <see cref="OidcOptions.AllowHttpIssuer"/>.
    /// </param>
    public static string? Refusal(Uri issuer, bool allowHttp)
    {
        if (!issuer.IsAbsoluteUri)
            return "must be an absolute URL";

        if (TryRefuseScheme(issuer, allowHttp, out var scheme))
            return scheme;

        if (!string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment))
            return "must have no query or fragment";

        if (issuer.UserInfo.Length > 0)
            return "must have no user name or password";

        if (!IsWrittenAsUrl(issuer.OriginalString))
            return "must be written as a URL with no whitespace or control characters";

        return null;
    }

    private static bool TryRefuseScheme(Uri issuer, bool allowHttp, [NotNullWhen(true)] out string? refusal)
    {
        refusal = (issuer.Scheme, allowHttp) switch
        {
            (var scheme, _) when scheme == Uri.UriSchemeHttps => null,
            (var scheme, true) when scheme == Uri.UriSchemeHttp => null,
            (_, true) => "must use the https or http scheme",
            (_, false) => $"must use the https scheme; {nameof(OidcOptions.AllowHttpIssuer)} lets http through " +
                          "for local development",
        };
        return refusal is not null;
    }

    /// <remarks>
    /// The string is what every token carries, and the parser forgives what a token must not: it trims surrounding
    /// whitespace and accepts an unescaped space or tab in the path.
    /// </remarks>
    private static bool IsWrittenAsUrl(string written)
        => !written.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)) &&
           Uri.IsWellFormedUriString(written, UriKind.Absolute);
}
