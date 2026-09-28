// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Resolves each request to the tenant it belongs to, by host name or by a path naming the tenant.
/// </summary>
/// <remarks>
/// <para>
/// A host bound to a tenant decides it, and a path on that host is not read for another one - otherwise one
/// request could be resolved two ways. On any other host, a path starting <c>/{segment}/{tenant}</c>, with the
/// segment spelled exactly, names the tenant, and both segments move into the request's path base: the
/// endpoints are routed exactly as without tenants, and every address built from the path base - the endpoints
/// discovery advertises, the cookie path, the address a proof or an assertion is checked against - carries the
/// tenant.
/// </para>
/// <para>
/// A request whose path names a tenant nobody declared, or one bound to hosts, is answered 404 before any
/// endpoint sees it. A request that
/// names none passes through without a tenant, since the application may serve other things; the OpenID
/// endpoints refuse it.
/// </para>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantResolutionMiddleware(
    RequestDelegate next,
    ITenantCatalog catalog,
    IOptionsMonitor<MultiTenancyOptions> options)
{
    /// <summary>
    /// The key a request this middleware has seen, resolved or not, is marked under.
    /// </summary>
    private static readonly object ResolutionRan = new();

    /// <summary>
    /// Whether this middleware ran for <paramref name="context"/>, which tells a request that names no tenant
    /// from one reaching the server with resolution missing from its pipeline.
    /// </summary>
    public static bool HasRun(HttpContext context) => context.Items.ContainsKey(ResolutionRan);

    /// <summary>
    /// Resolves the tenant of <paramref name="context"/> and runs the rest of the pipeline under it.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        context.Items[ResolutionRan] = true;
        var request = context.Request;
        var cancellationToken = context.RequestAborted;

        if (await catalog.FindByHostAsync(request.Host.Host, cancellationToken) is { } boundTenant)
        {
            context.Features.Set(new TenantContext { Tenant = boundTenant });
            await next(context);
            return;
        }

        if (options.CurrentValue.PathSegment is not { } segment ||
            !TryReadTenant(request.Path, segment, out var tenantId, out var rest))
        {
            await next(context);
            return;
        }

        // A tenant bound to hosts is served at those hosts only, where its issuer is: reached by path elsewhere
        // it would publish a discovery document whose issuer is not the address it was fetched from.
        if (await catalog.FindByIdAsync(tenantId, cancellationToken) is not { Hosts.Count: 0 } pathTenant)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var originalPathBase = request.PathBase;
        var originalPath = request.Path;
        request.PathBase = originalPathBase.Add(new PathString($"/{segment}/{tenantId}"));
        request.Path = rest;
        context.Features.Set(new TenantContext { Tenant = pathTenant });
        try
        {
            await next(context);
        }
        finally
        {
            request.PathBase = originalPathBase;
            request.Path = originalPath;
        }
    }

    /// <summary>
    /// Reads <c>/{segment}/{tenant}</c> off the start of <paramref name="path"/>, the segment compared exactly:
    /// a browser compares cookie paths exactly too, so a tenant reached through another spelling of the segment
    /// would never be sent the cookie set under the tenant's path.
    /// </summary>
    private static bool TryReadTenant(PathString path, string segment, out string tenantId, out PathString rest)
    {
        tenantId = string.Empty;
        rest = PathString.Empty;

        var prefix = "/" + segment + "/";
        var value = path.Value;
        if (value is null || !value.StartsWith(prefix, StringComparison.Ordinal))
            return false;

        var end = value.IndexOf('/', prefix.Length);
        tenantId = end < 0 ? value[prefix.Length..] : value[prefix.Length..end];
        rest = end < 0 ? PathString.Empty : new PathString(value[end..]);
        return tenantId.Length > 0;
    }
}
