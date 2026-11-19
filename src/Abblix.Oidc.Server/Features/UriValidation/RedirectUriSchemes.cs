// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UriValidation;

/// <summary>
/// The URI schemes a native app's redirect URI may use (RFC 8252 section 7).
/// </summary>
internal static class RedirectUriSchemes
{
    /// <summary>
    /// Whether the user agent may be sent to <paramref name="uri"/>: an https URI, an http URI to a loopback host, or a
    /// private-use scheme carrying a period, which RFC 8252 section 8.4 asks for "At a minimum".
    /// </summary>
    /// <remarks>
    /// Dynamic registration, a client's metadata document and startup each hold a native client's redirect URIs to it.
    /// The registration checks, which judge a metadata document too, refuse a native client's https URI besides, since
    /// OpenID Connect Dynamic Client Registration 1.0 section 2 has a native client "only register redirect_uris using
    /// custom URI schemes or loopback URLs using the http scheme". A client the host declares is not registered under
    /// that document, so startup lets it use the claimed https redirect RFC 8252 section 7.2 offers.
    /// </remarks>
    /// <param name="uri">An absolute URI.</param>
    public static bool IsAllowed(Uri uri)
    {
        if (uri.Scheme == Uri.UriSchemeHttps)
            return true;

        if (uri.Scheme == Uri.UriSchemeHttp)
            return LoopbackHosts.IsNativeLoopbackHost(uri);

        return uri.Scheme.Contains('.');
    }
}
