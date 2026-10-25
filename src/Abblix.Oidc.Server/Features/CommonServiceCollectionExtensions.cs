// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.Hashing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.UserInteraction;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring the services every feature relies on.
/// </summary>
public static class CommonServiceCollectionExtensions
{
    /// <summary>
    /// Registers common services required by the application, like system clock, hashing services, etc.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> with the common services registered.</returns>
    /// <remarks>A call after the first changes nothing.</remarks>
    public static IServiceCollection AddCommonServices(this IServiceCollection services)
    {
        // A second call would add the check that a consent provider is chosen again, and a server without one would
        // be refused twice over; the first call's mark ends every later one
        if (services.Any(descriptor => descriptor.ImplementationInstance is CommonServicesMarker))
            return services;

        services.AddSingleton(new CommonServicesMarker());
        services.AddConsentProviderChoice();
        services.TryAddSingleton<IUserInteractionRequirement, NoUserInteractionRequirement>();

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IHashService, HashService>();
        services.TryAddSingleton<CredentialFingerprints>();
        services.TryAddKeyedSingleton<IBinarySerializer, JsonBinarySerializer>(nameof(JsonBinarySerializer));
        services.TryAddKeyedSingleton<IBinarySerializer, ProtobufSerializer>(nameof(ProtobufSerializer));
        services.TryAddSingleton<IBinarySerializer, CompositeBinarySerializer>();
        // Every tenant's entities are kept in one store, each under keys its stores build from the tenant. The store
        // is the one registered under the shared key, which a host substitutes in any order, or one the host
        // registered for the server before this call, which the forwarding below then leaves in place
        services.TryAddKeyedSingleton<IEntityStorage, DistributedCacheStorage>(TenantServiceKeys.Shared);
        services.TryAddSingleton<IEntityStorage>(
            serviceProvider => serviceProvider.GetRequiredKeyedService<IEntityStorage>(TenantServiceKeys.Shared));
        services.AddTelemetryDecorator<IEntityStorage, MeasuredEntityStorage>();
        services.TryAddSingleton<ITenantAccessor, AmbientTenantAccessor>();

        // The next-poll instant of a polled request, kept apart from the request itself: a poll
        // writing the request back to note it overwrote whatever the approval had changed.
        services.TryAddSingleton<IPollScheduleStore, PollScheduleStore>();
        return services
            .AddJsonWebTokens()
            .AddTelemetryDecorator<IJsonWebTokenSigner, MeasuredJsonWebTokenSigner>();
    }

    /// <summary>
    /// Marks the common services as registered.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S2094:Classes should not be empty",
        Justification = "The empty body is the point: the type is the mark a later call finds, and it carries no data.")]
    private sealed class CommonServicesMarker;
}
