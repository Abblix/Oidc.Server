// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.AspNetCore.MultiTenancy;

/// <summary>
/// Resolves each request to the tenant it is addressed to.
/// </summary>
public static class MultiTenancyExtensions
{
    /// <summary>
    /// Registers what tells the tenant of the current request: the one the innermost <see cref="TenantScope"/>
    /// names, or else the one <see cref="TenantResolutionMiddleware"/> resolved the request to.
    /// </summary>
    /// <remarks>
    /// It takes the place of the server's own <see cref="AmbientTenantAccessor"/>, which knows no request, whichever
    /// was registered first, and leaves an accessor of the host's own in place.
    /// </remarks>
    internal static IServiceCollection AddTenantResolution(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();

        var registered = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(ITenantAccessor));
        if (registered is null || registered.ImplementationType == typeof(AmbientTenantAccessor))
            services.Replace(ServiceDescriptor.Singleton<ITenantAccessor, HttpContextTenantAccessor>());

        services.TryAddSingleton<MultiTenancyCall>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, MultiTenancyCallCheck>());
        return services;
    }

    /// <summary>
    /// Resolves each request to its tenant, and routes it after that.
    /// </summary>
    /// <remarks>
    /// Routing is added right after resolution, because the path of a tenant's issuer moves into the path base
    /// and the route has to be matched on what is left: a web application that routes on its own would otherwise
    /// match the endpoints against the full path and answer every tenant served under a path 404. So call this
    /// BEFORE any <c>UseRouting</c> of the host's - a call placed after one is refused, since a route matched there,
    /// a fallback page included, would take every tenant's request - and before <c>UseAuthentication</c>, whose
    /// cookie then takes the tenant's path and does not reach another tenant on the same host. A path base set
    /// before this call, by <c>UsePathBase</c> for one, is compared with the issuer's path exactly, the case of an
    /// encoded slash aside, so a request spelling it in another case reaches no tenant. A host whose pipeline leaves
    /// this call out does not start, unless it registers its own <see cref="ITenantAccessor"/>.
    /// </remarks>
    public static IApplicationBuilder UseMultiTenancy(this IApplicationBuilder app)
    {
        if (app.Properties.ContainsKey(EndpointRouteBuilderProperty))
        {
            throw new InvalidOperationException(
                $"{nameof(UseMultiTenancy)}() must come before UseRouting(): routing already ran here, so a route " +
                "would be matched against the full path before the tenant it is addressed to is resolved.");
        }

        app.ApplicationServices.GetRequiredService<MultiTenancyCall>().Record();
        return app.UseMiddleware<TenantResolutionMiddleware>().UseRouting();
    }

    /// <summary>
    /// The application property ASP.NET Core's <c>UseRouting</c> leaves behind, by which a routing call already
    /// in the pipeline is seen.
    /// </summary>
    private const string EndpointRouteBuilderProperty = "__EndpointRouteBuilder";
}
