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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// The tenant of a request as the transports see it, asked of <see cref="ITenantAccessor"/> - the same source
/// the issuer comes from, so a host that supplies its own accessor is answered consistently everywhere.
/// </summary>
public static partial class TenantRequirement
{
    /// <summary>
    /// The tenant <paramref name="context"/> was resolved to, or null when the request names no tenant.
    /// </summary>
    public static TenantContext? CurrentTenant(HttpContext context)
        => context.RequestServices.GetRequiredService<ITenantAccessor>().Current;

    /// <summary>
    /// True when <paramref name="context"/> was not resolved to a tenant.
    /// </summary>
    /// <remarks>
    /// Asked at the entry of every OpenID endpoint, in both transports: a registration without a tenant would
    /// store a client nobody owns, and an authorization request would park a code no tenant can redeem.
    /// </remarks>
    public static bool IsUnmet(HttpContext context)
    {
        var accessor = context.RequestServices.GetRequiredService<ITenantAccessor>();
        if (accessor.Current is not null)
            return false;

        // Resolution that never ran looks exactly like a request naming no tenant, and would answer every
        // endpoint 404 with nothing to say why; the log names the cause. A server serving its one tenant without
        // resolution needs no call, so its log says what kept this request from the tenant instead.
        if (accessor is HttpContextTenantAccessor && !TenantResolutionMiddleware.HasRun(context) &&
            context.RequestServices.GetService<ILoggerFactory>() is { } loggerFactory)
        {
            var logger = loggerFactory.CreateLogger(typeof(TenantRequirement));
            if (context.RequestServices.GetService<LoneTenant>() is { WhyTheCallIsNeeded: null })
                LogLoneTenantNotReached(logger, LoneTenantMissed(context));
            else
                LogResolutionNotInPipeline(logger);
        }

        return true;
    }

    /// <summary>
    /// What kept a request of a server serving its one tenant without resolution from that tenant.
    /// </summary>
    private static string LoneTenantMissed(HttpContext context)
        => context.Request.PathBase.Value?.TrimEnd('/') is { Length: > 0 } pathBase
            ? $"the request came under the path base {pathBase}, which the tenant's issuer at the root of its host " +
              "does not cover"
            : "the tenant is not served now, and the catalog's log of the tenants it left out says why";

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.LoneTenantNotReached,
        Level = LogLevel.Warning,
        Message = "An OpenID endpoint of the server serving its one tenant without UseMultiTenancy() reached no " +
                  "tenant, so it answers 404: {Cause}.")]
    private static partial void LogLoneTenantNotReached(ILogger logger, string cause);

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.ResolutionNotInPipeline,
        Level = LogLevel.Warning,
        Message = "An OpenID endpoint was reached without tenant resolution: UseMultiTenancy() is not in the " +
                  "request pipeline, so every OpenID endpoint answers 404.")]
    private static partial void LogResolutionNotInPipeline(ILogger logger);
}
