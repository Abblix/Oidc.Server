// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// request could be resolved two ways. On any other host, a path starting <c>/{segment}/{tenant}</c> names the
/// tenant, and both segments move into the request's path base, so the endpoints are routed exactly as without
/// tenants, and everything built from the path base - the request-based issuer, the cookie path, every
/// endpoint address - carries the tenant.
/// </para>
/// <para>
/// A request that names a tenant nobody declared is answered 404 before any endpoint sees it. A request that
/// names none passes through without a tenant, since the application may serve other things; an OpenID
/// endpoint reached that way is refused by <see cref="TenantGuardIssuerProvider"/>.
/// </para>
/// </remarks>
public sealed class TenantResolutionMiddleware(
    RequestDelegate next,
    ITenantCatalog catalog,
    IOptionsMonitor<MultiTenancyOptions> options)
{
    /// <summary>
    /// Resolves the tenant of <paramref name="context"/> and runs the rest of the pipeline under it.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;

        if (await catalog.FindByHostAsync(request.Host.Host) is { } boundTenant)
        {
            context.Features.Set(new TenantContext(boundTenant.Id));
            await next(context);
            return;
        }

        if (options.CurrentValue.PathSegment is not { } segment ||
            !request.Path.StartsWithSegments("/" + segment, out var afterSegment) ||
            !TrySplitFirstSegment(afterSegment, out var tenantId, out var rest))
        {
            await next(context);
            return;
        }

        if (await catalog.FindByIdAsync(tenantId) is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var originalPathBase = request.PathBase;
        var originalPath = request.Path;
        request.PathBase = originalPathBase.Add(new PathString($"/{segment}/{tenantId}"));
        request.Path = rest;
        context.Features.Set(new TenantContext(tenantId));
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
    /// Splits <c>/{first}/rest</c> into its first segment and what follows it.
    /// </summary>
    private static bool TrySplitFirstSegment(PathString path, out string first, out PathString rest)
    {
        var value = path.Value;
        if (string.IsNullOrEmpty(value) || value.Length < 2)
        {
            first = string.Empty;
            rest = PathString.Empty;
            return false;
        }

        var end = value.IndexOf('/', 1);
        first = end < 0 ? value[1..] : value[1..end];
        rest = end < 0 ? PathString.Empty : new PathString(value[end..]);
        return true;
    }
}
