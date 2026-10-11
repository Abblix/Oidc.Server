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
/// Whether a request names the host every address of this server is built from, asked at the entry of every
/// OpenID endpoint in both transports.
/// </summary>
/// <remarks>
/// HTTP/1.0 makes the Host header optional and Kestrel passes such a request on with an empty host. The request
/// address a client assertion and a DPoP proof are checked against, the issuer taken from the request and the
/// addresses discovery advertises all start from the host, so a request without one is refused before an endpoint
/// starts any of its work.
/// </remarks>
public static class HostRequirement
{
    /// <summary>
    /// True when <paramref name="context"/> names no host.
    /// </summary>
    public static bool IsUnmet(HttpContext context) => !context.Request.Host.HasValue;
}
