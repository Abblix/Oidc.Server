// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

        if (issuer.Scheme != Uri.UriSchemeHttps && !(allowHttp && issuer.Scheme == Uri.UriSchemeHttp))
        {
            return allowHttp
                ? "must use the https or http scheme"
                : $"must use the https scheme; {nameof(OidcOptions.AllowHttpIssuer)} lets http through for local " +
                  "development";
        }

        if (!string.IsNullOrEmpty(issuer.Query) || !string.IsNullOrEmpty(issuer.Fragment))
            return "must have no query or fragment";

        return null;
    }
}
