// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Serves several isolated tenants from one deployment.
/// </summary>
/// <remarks>
/// A host that never calls these works as before: one tenant, nothing about it in the path.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static class MultiTenancyExtensions
{
    /// <summary>
    /// Registers tenant resolution, and makes every issuer the resolved tenant's.
    /// </summary>
    /// <remarks>
    /// Each tenant declares its issuer in <see cref="TenantDefinition.Issuer"/>, so
    /// <see cref="OidcOptions.Issuer"/> must be left unset, and startup refuses it otherwise.
    /// </remarks>
    public static IServiceCollection AddMultiTenancy(
        this IServiceCollection services,
        Action<MultiTenancyOptions> configure)
    {
        services.AddOptions<MultiTenancyOptions>().Configure(configure).ValidateOnStart();
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, MultiTenancyOptionsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, TenantIssuerOptionsValidator>(),
        ]);

        services.AddHttpContextAccessor();
        services.TryAddSingleton<ITenantCatalog, OptionsTenantCatalog>();
        services.TryAddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
        services.Replace(ServiceDescriptor.Singleton<IIssuerProvider, TenantIssuerProvider>());
        return services;
    }

    /// <summary>
    /// Resolves each request to its tenant, and routes it after that.
    /// </summary>
    /// <remarks>
    /// Routing is added right after resolution, because a tenant named in the path moves into the path base and
    /// the route has to be matched on what is left: a web application that routes on its own would otherwise
    /// match the endpoints against the full path and answer every tenant 404. So call this BEFORE any
    /// <c>UseRouting</c> of the host's, and before <c>UseAuthentication</c>, whose cookie then takes the tenant's
    /// path and does not reach another tenant on the same host.
    /// </remarks>
    public static IApplicationBuilder UseMultiTenancy(this IApplicationBuilder app)
        => app.UseMiddleware<TenantResolutionMiddleware>().UseRouting();
}
