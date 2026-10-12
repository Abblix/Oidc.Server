// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Whether a request names a host the addresses of this server can be built from, asked at the entry of every
/// OpenID endpoint in both transports.
/// </summary>
/// <remarks>
/// The request address a client assertion and a DPoP proof are checked against, the issuer taken from the request
/// and the addresses discovery advertises all start from the application address of the request. Kestrel passes on
/// a request with no host, which HTTP/1.0 allows, and one whose Host header no URI can carry, such as a host name
/// with an empty label or a port out of range; either is refused before an endpoint starts any of its work. The
/// verdict is the URI parser's own, on the very address the endpoints would build.
/// </remarks>
internal static class HostRequirement
{
    /// <summary>
    /// True when no absolute URI can be built from the application address of <paramref name="context"/>.
    /// </summary>
    public static bool IsUnmet(HttpContext context)
        => !Uri.TryCreate(context.Request.GetAppUrl(), UriKind.Absolute, out _);
}
