// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
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
    /// Call this after <c>AddOidcServices</c> and every other <c>Add*</c> of the server: it keeps each tenant's
    /// data apart by wrapping the services those calls registered, so it refuses when one is not registered yet,
    /// and startup refuses a server in which a later registration replaced or wrapped a wrapper. Call it once.
    /// </remarks>
    public static IServiceCollection AddMultiTenancy(
        this IServiceCollection services,
        Action<MultiTenancyOptions> configure)
    {
        // A second call would wrap the storage again, and every key it holds would change.
        if (services.Any(descriptor => descriptor.ImplementationType == typeof(TenantSeamsValidator)))
        {
            throw new InvalidOperationException(
                $"{nameof(AddMultiTenancy)}() has already been called; configure every tenant in that one call.");
        }

        services.AddOptions<MultiTenancyOptions>().Configure(configure).ValidateOnStart();

        // A server minting its keys keeps a ring for each creation of a tenant, named as its issuer settings name
        // it, so no two tenants share a key
        services.AddOptions<KeyRingOptions>().Configure<IOptions<MultiTenancyOptions>>(
            (ring, tenants) => ring.Partitions = [..tenants.Value.Tenants.Select(TenantKey.PartitionOf)]);
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantListValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantSeamsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantRegistriesValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, TenantOwnedOptionsValidator>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantDefinitionsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantSettingsCheck>(),
            ServiceDescriptor.Singleton<ITenantsCheck, TenantKeysCheck>(),
        ]);

        services.AddHttpContextAccessor();
        services.TryAddSingleton<ITenantStore, OptionsTenantStore>();
        services.TryAddSingleton<StoreTenantCatalog>();
        services.TryAddSingleton<ITenantCatalog>(serviceProvider => serviceProvider.GetRequiredService<StoreTenantCatalog>());
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TenantCatalogRefreshService>());
        services.TryAddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
        services.Replace(ServiceDescriptor.Singleton<IIssuerProvider, TenantIssuerProvider>());
        services.Replace(ServiceDescriptor.Singleton<IIssuerSettings, TenantIssuerSettings>());
        services.Replace(ServiceDescriptor.Transient(typeof(IIssuerLocal<>), typeof(TenantIssuerLocal<>)));

        foreach (var seam in TenantSeams.All)
            seam.Wrap(services);

        return services;
    }

    /// <summary>
    /// Resolves each request to its tenant, and routes it after that.
    /// </summary>
    /// <remarks>
    /// Routing is added right after resolution, because the path of a tenant's issuer moves into the path base
    /// and the route has to be matched on what is left: a web application that routes on its own would otherwise
    /// match the endpoints against the full path and answer every tenant served under a path 404. So call this
    /// BEFORE any
    /// <c>UseRouting</c> of the host's - a call placed after one is refused, since a route matched there, a
    /// fallback page included, would take every tenant's request - and before <c>UseAuthentication</c>, whose
    /// cookie then takes the tenant's path and does not reach another tenant on the same host. A path base set
    /// before this call, by <c>UsePathBase</c> for one, is compared with the issuer's path exactly, the case of an
    /// encoded slash aside, so a request spelling it in another case reaches no tenant.
    /// </remarks>
    public static IApplicationBuilder UseMultiTenancy(this IApplicationBuilder app)
    {
        if (app.Properties.ContainsKey(EndpointRouteBuilderProperty))
        {
            throw new InvalidOperationException(
                $"{nameof(UseMultiTenancy)}() must come before UseRouting(): routing already ran here, so a route " +
                "would be matched against the full path before the tenant it is addressed to is resolved.");
        }

        return app.UseMiddleware<TenantResolutionMiddleware>().UseRouting();
    }

    /// <summary>
    /// The application property ASP.NET Core's <c>UseRouting</c> leaves behind, by which a routing call already
    /// in the pipeline is seen.
    /// </summary>
    private const string EndpointRouteBuilderProperty = "__EndpointRouteBuilder";
}
