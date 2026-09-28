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
/// Reads URL components from an <see cref="HttpRequest"/>. Touches only <see cref="HttpRequest"/> (no MVC, no Minimal
/// API types), so it is shared by both transport adapters.
/// </summary>
public static class HttpRequestExtensions
{
    /// <summary>
    /// Gets the application's base URL (scheme, host, and base path) from the request.
    /// </summary>
    public static string GetAppUrl(this HttpRequest request) => request.GetFullUrl(request.PathBase);

    /// <summary>
    /// Gets the base URL of the request (scheme, host, and request path).
    /// </summary>
    public static string GetBaseUrl(this HttpRequest request) => request.GetFullUrl(request.Path);

    /// <summary>
    /// Resolves a relative address - an interaction page (login, consent, registration), or in the MVC transport
    /// an endpoint route - to an absolute one.
    /// </summary>
    /// <remarks>
    /// <c>~/</c> means the application base. Any other relative path resolves against the server as a browser
    /// would - except for a request resolved to a tenant, where every relative path means the tenant's base: an
    /// endpoint advertised off it would be unreachable, and a login page reached at the server root would run
    /// without the tenant, its sign-in cookie, written for the root, reaching every tenant on the host.
    /// </remarks>
    public static Uri ResolveInteractionUri(this HttpRequest request, string path)
    {
        var appUrl = request.GetAppUrl();

        if (path.StartsWith("~/", StringComparison.Ordinal))
            return new Uri(appUrl + path[1..], UriKind.Absolute);

#pragma warning disable ABXMT001 // Reading whether a tenant was resolved changes nothing for a host without them.
        var underTenant = MultiTenancy.TenantRequirement.CurrentTenant(request.HttpContext) is not null;
#pragma warning restore ABXMT001

#pragma warning disable S1075 // The separator joining the tenant's base and a path, not a location of its own.
        if (underTenant && !Uri.IsWellFormedUriString(path, UriKind.Absolute))
            return new Uri(appUrl + '/' + path.TrimStart('/'), UriKind.Absolute);
#pragma warning restore S1075

        return new Uri(new Uri(appUrl, UriKind.Absolute), path);
    }

    private static string GetFullUrl(this HttpRequest request, PathString path)
        => request.Scheme + Uri.SchemeDelimiter + request.Host + path;
}
