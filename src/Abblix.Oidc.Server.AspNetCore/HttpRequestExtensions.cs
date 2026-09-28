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
    /// Resolves a relative address of an interaction page (login, consent, registration) to an absolute one.
    /// </summary>
    /// <remarks>
    /// <c>~/</c> means the application base. Any other relative path means the server root - except for a request
    /// resolved to a tenant, where it means the tenant's base: a login page reached at the server root would run
    /// without the tenant, and its sign-in cookie, written for the root, would reach every tenant on the host.
    /// </remarks>
    public static Uri ResolveInteractionUri(this HttpRequest request, string path)
    {
        var appUrl = request.GetAppUrl();
#pragma warning disable ABXMT001 // Reading whether a tenant was resolved changes nothing for a host without them.
        var underTenant = request.HttpContext.Features.Get<Features.MultiTenancy.TenantContext>() is not null;
#pragma warning restore ABXMT001

        if (path.StartsWith("~/", StringComparison.Ordinal))
            return new Uri(appUrl + path[1..], UriKind.Absolute);

        if (underTenant && path.StartsWith('/'))
            return new Uri(appUrl + path, UriKind.Absolute);

        return new Uri(new Uri(appUrl, UriKind.Absolute), path);
    }

    private static string GetFullUrl(this HttpRequest request, PathString path)
        => request.Scheme + Uri.SchemeDelimiter + request.Host + path;
}
