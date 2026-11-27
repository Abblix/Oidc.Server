// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// The URI schemes a client's redirect URI may use, the one rule the check of the settings, dynamic registration, client
/// ID metadata documents and the authorization endpoint hold a redirect URI to.
/// </summary>
internal static class RedirectUriSchemes
{
    /// <summary>
    /// Whether a client of the given kind may redirect to <paramref name="uri"/>: any client to https; only a native app
    /// to http, on a loopback host (RFC 9700 section 2.6: the server "MUST NOT allow redirection URIs that use the http
    /// scheme except for native clients that use loopback interface redirection"); and only a native app to a private-use
    /// scheme, one containing a period (RFC 8252 sections 7.1 and 8.4: "any private-use URI scheme that doesn't contain a
    /// period character (".") SHOULD be rejected").
    /// </summary>
    /// <param name="uri">An absolute URI.</param>
    /// <param name="native">Whether the client is a native app.</param>
    public static bool IsAllowed(Uri uri, bool native)
    {
        if (uri.Scheme == Uri.UriSchemeHttps)
            return true;

        if (uri.Scheme == Uri.UriSchemeHttp)
            return native && LoopbackHosts.IsNativeLoopbackHost(uri);

        return native && uri.Scheme.Contains('.');
    }
}
