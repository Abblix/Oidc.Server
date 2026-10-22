// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.RateLimiting;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features.RateLimiting;

/// <summary>
/// Registers a budget each tenant spends on its own.
/// </summary>
internal static class TenantRateLimiterServiceCollectionExtensions
{
    /// <summary>
    /// Registers the budget <paramref name="key"/>, which the server resolves in the form keeping one limiter per
    /// tenant, each built by what is registered under <see cref="TenantServiceKeys.PerTenant"/> of the key:
    /// <paramref name="create"/>, unless the host registered its own there, before or after this call.
    /// </summary>
    public static IServiceCollection AddTenantRateLimiter<TResource>(
        this IServiceCollection services,
        string key,
        Func<IServiceProvider, PartitionedRateLimiter<TResource>> create)
    {
        var perTenant = TenantServiceKeys.PerTenant(key);

        // Transient, so each tenant is handed a limiter of its own rather than every tenant one budget
        services.TryAddKeyedTransient<PartitionedRateLimiter<TResource>>(
            perTenant,
            (serviceProvider, _) => create(serviceProvider));

        services.TryAddKeyedSingleton<PartitionedRateLimiter<TResource>>(
            key,
            (serviceProvider, _) => new TenantPartitionedRateLimiter<TResource>(
                () => serviceProvider.GetRequiredKeyedService<PartitionedRateLimiter<TResource>>(perTenant),
                serviceProvider.GetRequiredService<ITenantAccessor>(),
                serviceProvider.GetRequiredService<ITenantCatalog>()));

        return services;
    }
}
