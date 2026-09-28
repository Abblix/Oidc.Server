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
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static partial class TenantRequirement
{
    /// <summary>
    /// The tenant <paramref name="context"/> was resolved to, or null when multi-tenancy is off or the request
    /// names no tenant.
    /// </summary>
    public static TenantContext? CurrentTenant(HttpContext context)
        => context.RequestServices.GetService<ITenantAccessor>()?.Current;

    /// <summary>
    /// True when multi-tenancy is enabled and <paramref name="context"/> was not resolved to a tenant.
    /// </summary>
    /// <remarks>
    /// Asked at the entry of every OpenID endpoint, in both transports: a registration without a tenant would
    /// store a client nobody owns, and an authorization request would park a code no tenant can redeem. A
    /// deployment that never enabled multi-tenancy needs no tenant.
    /// </remarks>
    public static bool IsUnmet(HttpContext context)
    {
        if (context.RequestServices.GetService<ITenantAccessor>() is not { Current: null } accessor)
            return false;

        // Resolution that never ran looks exactly like a request naming no tenant, and would answer every
        // endpoint 404 with nothing to say why; the log names the missing call.
        if (accessor is HttpContextTenantAccessor && !TenantResolutionMiddleware.HasRun(context) &&
            context.RequestServices.GetService<ILoggerFactory>() is { } loggerFactory)
        {
            LogResolutionNotInPipeline(loggerFactory.CreateLogger(typeof(TenantRequirement)));
        }

        return true;
    }

    [LoggerMessage(
        EventId = LogEvents.MultiTenancy.ResolutionNotInPipeline,
        Level = LogLevel.Warning,
        Message = "An OpenID endpoint was reached without tenant resolution: multi-tenancy is added but " +
                  "UseMultiTenancy() is not in the request pipeline, so every OpenID endpoint answers 404.")]
    private static partial void LogResolutionNotInPipeline(ILogger logger);
}
