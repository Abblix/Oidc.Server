// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// The tenant of the innermost <see cref="TenantScope"/> entered, or else the one
/// <see cref="TenantResolutionMiddleware"/> resolved the current request to, or else, for a server that serves its one
/// tenant without that middleware, that tenant.
/// </summary>
/// <param name="httpContextAccessor">Holds the current request.</param>
/// <param name="services">Tells whether the server serves its one tenant without the middleware: the same answer the
/// startup check reads, so a host the check lets start without the middleware is served. A host registering the core
/// alone registers nothing that serves it, and resolves every request with the middleware.</param>
public sealed class HttpContextTenantAccessor(IHttpContextAccessor httpContextAccessor, IServiceProvider services)
    : ITenantAccessor
{
    /// <inheritdoc />
    public TenantContext? Current
        => TenantScope.Current ?? httpContextAccessor.HttpContext switch
        {
            null => null,
            var context => context.Features.Get<TenantContext>() ?? Lone(context),
        };

    /// <summary>
    /// True when this server's own accessor tells the tenant of <paramref name="context"/> and tenant resolution did
    /// not run for it, so nothing in the pipeline has waited for the tenants or matched the request to one.
    /// </summary>
    internal static bool AnswersWithoutResolution(HttpContext context)
        => context.RequestServices.GetRequiredService<ITenantAccessor>() is HttpContextTenantAccessor &&
           !TenantResolutionMiddleware.HasRun(context);

    /// <summary>
    /// The one tenant, for a request no resolution has seen and that reaches the server at the root of its host.
    /// </summary>
    /// <remarks>
    /// A request the middleware saw keeps its answer, a tenant or none. A request under a path base the host set is
    /// not covered by an issuer at the root, as the middleware would not cover it either. The answer is not kept on
    /// the request, since a reader placed before the middleware or the path base would then settle it for them.
    /// </remarks>
    private TenantContext? Lone(HttpContext context)
    {
        if (TenantResolutionMiddleware.HasRun(context) ||
            (context.Request.PathBase.Value ?? string.Empty).TrimEnd('/').Length > 0 ||
            services.GetService<LoneTenant>() is not { Served: { } tenant })
        {
            return null;
        }

        return new TenantContext { Tenant = tenant };
    }
}
