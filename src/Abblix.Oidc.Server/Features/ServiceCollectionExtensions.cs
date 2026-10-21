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
        services.TryAddSingleton<ReloadableClientInfoStorage>();
        services.TryAddSingleton<IClientRegistrations>(DefaultClientRegistrations.Create);
        services.TryAddSingleton<IClientKeysProvider, ClientKeysProvider>();

        services.AddOidcOptionsValidators();

        // A tenant's definition changes while the server runs, read again from the store of tenants, so the clients
        // it declares follow it, or one it dropped would still authenticate. TryAdd: a host that pre-registers its
        // own client store wins over the default (issue #226).
        services.TryAddSingleton<IClientInfoProvider>(
            provider => provider.GetRequiredService<ReloadableClientInfoStorage>());
        services.TryAddSingleton<IClientInfoManager>(
            provider => provider.GetRequiredService<ReloadableClientInfoStorage>());
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
