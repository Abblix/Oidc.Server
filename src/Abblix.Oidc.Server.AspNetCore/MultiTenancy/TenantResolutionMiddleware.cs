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

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Resolves each request to the tenant whose issuer it is addressed to.
/// </summary>
/// <remarks>
/// <para>
/// A request belongs to the tenant whose issuer names the request's host and the longest whole-segment start of
/// its path, and the issuer's path becomes the request's path base: the endpoints are routed exactly as without
/// tenants, and every address built from the path base - the endpoints discovery advertises, the cookie path,
/// the address a proof or an assertion is checked against - lies under the issuer. For
/// <c>https://auth.example.com/tenants/acme</c>, <c>/tenants/acme/connect/token</c> reaches the token endpoint
/// as <c>/connect/token</c>.
/// </para>
/// <para>
/// The form RFC 8414 section 3.1 defines, the well-known suffix inserted between the host and the issuer's path -
/// <c>/.well-known/oauth-authorization-server/tenants/acme</c> - reaches the same tenant's metadata, provided the
/// path after the suffix is exactly that issuer's.
/// </para>
/// <para>
/// A request no issuer covers passes through without a tenant, since the application may serve other things;
/// the OpenID endpoints refuse it.
/// </para>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantResolutionMiddleware(RequestDelegate next, ITenantCatalog catalog)
{
    private static readonly PathString WellKnown = new("/.well-known");

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

        var resolved =
            await FindByInsertedWellKnownAsync(request, context.RequestAborted) ??
            await FindByIssuerPathAsync(request, context.RequestAborted);

        if (resolved is not var (tenant, issuerPath, path))
        {
            await next(context);
            return;
        }

        var originalPathBase = request.PathBase;
        var originalPath = request.Path;
        request.PathBase = issuerPath;
        request.Path = path;
        context.Features.Set(new TenantContext { Tenant = tenant });
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
    /// The tenant whose issuer's path starts the request's full path, with the path left after it.
    /// </summary>
    /// <remarks>
    /// The issuer's path has to extend the path base the host already mounted the server under: an issuer above
    /// it names addresses this server is not reached at.
    /// </remarks>
    private async Task<(TenantDefinition, PathString, PathString)?> FindByIssuerPathAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        var fullPath = TenantAddress.CanonicalPath(request.PathBase.Add(request.Path).Value ?? string.Empty);
        if (await catalog.FindByAddressAsync(request.Host.Host, fullPath, cancellationToken) is not { } tenant)
            return null;

        var issuerPath = new PathString(TenantAddress.Of(tenant.Issuer).Path);
        if (!issuerPath.StartsWithSegments(request.PathBase, StringComparison.Ordinal))
            return null;

        return (tenant, issuerPath, new PathString(fullPath[issuerPath.Value!.Length..]));
    }

    /// <summary>
    /// The tenant addressed as <c>/.well-known/{suffix}{issuer path}</c>, with the path the well-known endpoint
    /// is routed at.
    /// </summary>
    /// <remarks>
    /// Read only at the root of the host, where RFC 8414 puts it, and only for an exact issuer path: a longer
    /// path is some other address under the suffix, not this tenant's metadata.
    /// </remarks>
    private async Task<(TenantDefinition, PathString, PathString)?> FindByInsertedWellKnownAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        if (request.PathBase.HasValue ||
            !request.Path.StartsWithSegments(WellKnown, StringComparison.Ordinal, out var afterWellKnown))
        {
            return null;
        }

        var value = TenantAddress.CanonicalPath(afterWellKnown.Value ?? string.Empty);
        var suffixEnd = value.IndexOf('/', 1);
        if (suffixEnd < 0)
            return null;

        var issuerPath = value[suffixEnd..];
        if (await catalog.FindByAddressAsync(request.Host.Host, issuerPath, cancellationToken) is not { } tenant ||
            TenantAddress.Of(tenant.Issuer).Path != issuerPath)
        {
            return null;
        }

        return (tenant, new PathString(issuerPath), WellKnown.Add(new PathString(value[..suffixEnd])));
    }
}
