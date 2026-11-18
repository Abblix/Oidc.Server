// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Microsoft.Extensions.DependencyInjection;
using Abblix.Oidc.Server.Features.Consents;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The parts of the server a test of its tenants composes, without the endpoints around them.
/// </summary>
internal static class ServerStorageRegistration
{
    /// <summary>
    /// Registers the server's own storage services - the library's registrations, not stand-ins, since they are
    /// what keeps each tenant's data apart.
    /// </summary>
    public static IServiceCollection AddServerStorage(this IServiceCollection services)
        => services
            .AddLogging()
            .AddDistributedMemoryCache()
            .AddCommonServices()
            .AddConsentGrantedForEveryClient()
            .AddStorages()
            .AddNonces()
            .AddReplayPrevention()
            .AddClientAuthentication();

    /// <summary>
    /// Serves tenants from a store a host fills while the server runs, empty here: the test enters its tenants
    /// itself, and none of them is read from the settings.
    /// </summary>
    public static IServiceCollection ServeTenants(this IServiceCollection services)
    {
        services.TryAddSingleton<ITenantStore, NoStoredTenants>();
        return services.ServeTenants(_ => { });
    }

    /// <summary>
    /// Serves the tenants <paramref name="configure"/> declares, resolved as the transports resolve them.
    /// </summary>
    public static IServiceCollection ServeTenants(this IServiceCollection services, Action<OidcOptions> configure)
    {
        services.AddOptions<OidcOptions>().Configure(configure).ValidateOnStart();
        return services.AddTenants().AddTenantResolution();
    }

    /// <summary>A store of tenants holding none yet.</summary>
    private sealed class NoStoredTenants : ITenantStore
    {
        public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyCollection<StoredTenant>>([]);
    }
}
