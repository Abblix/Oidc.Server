// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Registers the tenants a deployment serves: where they are read from, how each is judged and readied, and the
/// issuer and settings every request is answered with, which are its tenant's.
/// </summary>
public static class TenantServiceCollectionExtensions
{
    /// <summary>
    /// Registers the tenants, read from <see cref="Common.Configuration.OidcOptions.Tenants"/> unless the host registers a store of its
    /// own, and makes every issuer the resolved tenant's.
    /// </summary>
    /// <remarks>
    /// The users, the consents and the steps a host requires before issuing stay the host's and are not partitioned
    /// here: its <c>IUserInfoProvider</c>, <c>IUserConsentsProvider</c>, <c>IUserInteractionRequirement</c> and
    /// <c>IUserCredentialsAuthenticator</c> are each handed the tenant, and a host keeping them apart answers for it.
    /// </remarks>
    /// <param name="services">The service collection to register the tenants in.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddTenants(this IServiceCollection services)
    {
        services.TryAddSingleton<ITenantStore, OptionsTenantStore>();
        services.TryAddSingleton<StoreTenantCatalog>();
        services.TryAddSingleton<ITenantCatalog>(
            serviceProvider => serviceProvider.GetRequiredService<StoreTenantCatalog>());
        services.TryAddSingleton<ITenantManager, TenantManager>();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TenantCatalogRefreshService>());

        // A server minting its keys keeps a part of its key ring for each creation of each tenant served, named as
        // TenantKey.PartitionOf names it, so no two tenants share a key and a tenant gained at runtime has one; the
        // part of a released tenant is deleted from the store
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITenantOpening, TenantKeyRingOpening>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITenantClosing, TenantKeyRingClosing>());
        services.TryAddSingleton<IKeyRingPartitions, TenantKeyRingPartitions>();

        services.TryAddSingleton<ITenantAccessor, AmbientTenantAccessor>();

        // Transient, so each service holding values gets its own holder
        services.TryAddTransient(typeof(IIssuerLocal<>), typeof(TenantIssuerLocal<>));

        return services.AddTenantValidation();
    }
}
