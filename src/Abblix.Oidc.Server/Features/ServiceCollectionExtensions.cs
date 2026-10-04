// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ReusePrevention;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring client information and the
/// storages of the OpenID Connect (OIDC) server.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Configures services related to client information management. This includes registering the client information storage mechanism,
    /// which serves as the provider and manager for client information, as well as the provider for client keys. This setup is crucial
    /// for the OIDC server to manage and validate client identities and their corresponding secrets or keys.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    public static IServiceCollection AddClientInformation(this IServiceCollection services)
    {
        services.TryAddSingleton<ClientInfoStorage>();
        services.TryAddSingleton<ReloadableClientInfoStorage>();
        services.TryAddSingleton<IClientRegistrations>(DefaultClientRegistrations.Create);
        services.TryAddSingleton<IClientKeysProvider, ClientKeysProvider>();

        services.AddOidcOptionsValidators();

        // TryAdd: a host that pre-registers its own client store must win over the default (issue #226) - same
        // host-first contract as TryAdd* seams.
        services.TryAddSingleton<IClientInfoProvider>(DefaultClientStore);
        services.TryAddSingleton<IClientInfoManager>(DefaultClientStore);
        return services;
    }

    /// <summary>
    /// The client store the server serves clients from unless the host registers its own.
    /// </summary>
    /// <remarks>
    /// Under multi-tenancy a tenant's definition changes while the server runs, read again from the store of
    /// tenants, so the clients it declares must follow it, or one it dropped would still authenticate. A server
    /// without tenants reads its clients once, and a host wanting them reloaded asks for
    /// <see cref="AddReloadableClientInformation"/>. Asked when the store is first resolved, by which time every
    /// registration is in, so the order of the calls registering clients and multi-tenancy does not matter.
    /// </remarks>
    private static IClientInfoStore DefaultClientStore(IServiceProvider serviceProvider)
        => MultiTenancyDetection.IsActive(serviceProvider)
            ? serviceProvider.GetRequiredService<ReloadableClientInfoStorage>()
            : serviceProvider.GetRequiredService<ClientInfoStorage>();

    /// <summary>
    /// Serves clients from a store that follows a reload of the settings: the clients each issuer's settings
    /// configure are read again once they change, while what dynamic registration added, changed or removed is
    /// kept.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <remarks>
    /// It replaces the client store, whichever was registered, so it may be called before or after
    /// <c>AddOidcServices</c>. The settings own every id they configure: the store changes nothing under one, and
    /// a client registered in memory under an id they come to configure is dropped.
    /// </remarks>
    public static IServiceCollection AddReloadableClientInformation(this IServiceCollection services)
    {
        services.TryAddSingleton<ReloadableClientInfoStorage>();
        services.Replace(ServiceDescriptor.Singleton<IClientInfoProvider>(
            provider => provider.GetRequiredService<ReloadableClientInfoStorage>()));
        services.Replace(ServiceDescriptor.Singleton<IClientInfoManager>(
            provider => provider.GetRequiredService<ReloadableClientInfoStorage>()));
        return services;
    }

    /// <summary>
    /// Registers services for various storage functionalities related to the OAuth 2.0 and OpenID Connect flows within
    /// the application. This method configures essential storage services that manage authorization codes and
    /// authorization requests, ensuring their persistence and accessibility across the application.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the storage services will be added.
    /// This collection is crucial for configuring dependency injection in ASP.NET Core applications, allowing services
    /// to be added, managed, and retrieved throughout the application lifecycle.</param>
    /// <returns>The modified <see cref="IServiceCollection"/> after adding the storage services, permitting additional
    /// configurations to be chained.</returns>
    public static IServiceCollection AddStorages(this IServiceCollection services)
    {
        services.TryAddSingleton<IEntityStorageKeyFactory, EntityStorageKeyFactory>();
        services.TryAddSingleton<IAuthorizationCodeService, AuthorizationCodeService>();
        services.TryAddSingleton<IAuthorizationValueReuseDetector, AuthorizationValueReuseDetector>();
        services.TryAddSingleton<IAuthorizationRequestStorage, AuthorizationRequestStorage>();
        services.TryAddSingleton<IConsumedRequestUriRegistry, ConsumedRequestUriRegistry>();
        services.TryAddSingleton<ISessionClientRegistry, SessionClientRegistry>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, RecordLifetimeOptionsValidator>());
        services.TryAddSingleton(TimeProvider.System);
        return services;
    }
}
