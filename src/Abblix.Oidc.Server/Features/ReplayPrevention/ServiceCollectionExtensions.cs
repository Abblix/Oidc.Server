// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// Wires replay protection, which several unrelated features need and none of them owns:
/// JWT-bearer assertions (RFC 7523 Section 3), client assertions, and DPoP proofs
/// (RFC 9449 Section 11.1) all reserve identifiers in the same place.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the replay cache and decorates it with this server's clock skew and log events.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The store keeps its reservations in the server's entity storage, through its add-if-absent, so a storage
    /// whose add-if-absent holds across nodes makes the replay checks of every node hold too. It is registered under
    /// <see cref="TenantServiceKeys.Shared"/> in place of the store
    /// <see cref="ReplayCacheServiceCollectionExtensions.AddDistributedReplayCache"/> registers for a receiver of
    /// security event tokens, so the server and a receiver beside it share it in either order of their
    /// registrations. A store the host registered serves instead: one under the shared key in any order, or one
    /// without a key registered before this call. A receiver's store the host decorated before this call counts as
    /// the host's own and is kept, so the server's reservations then stay in it rather than in the entity storage.
    /// </para>
    /// <para>
    /// Idempotent, because several unrelated feature registrations call it.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddReplayPrevention(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);

        // Several feature registrations call this, and the decoration below is not idempotent by
        // itself - applying it twice would skew the window twice and log every reservation twice.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(AlreadyRegistered)))
        {
            return services;
        }

        services.AddSingleton(AlreadyRegistered.Instance);

        // The shared store is one the host registered by now, unless it registered its own under the shared key;
        // otherwise it is the store over the entity storage, in place of the one a receiver registered by now. A
        // receiver registering after this finds the unkeyed registration below and adds nothing, so either order ends
        // with this one store.
        services.AddEntityStorage();
        var registered = Abblix.DependencyInjection.ServiceCollectionExtensions.RemoveAll<IReplayCache>(services);
        services.TryAdd(registered is [.., var last] && !ReplayCacheServiceCollectionExtensions.IsDefaultStore(last)
            ? AsShared(last)
            : ServiceDescriptor.KeyedSingleton<IReplayCache>(
                TenantServiceKeys.Shared,
                (provider, _) => provider.CreateService<EntityStorageReplayCache>(
                    Dependency.Override(ReplayCacheServiceCollectionExtensions.CacheKeyPrefix))));
        services.AddSingleton<IReplayCache>(
            provider => provider.GetRequiredKeyedService<IReplayCache>(TenantServiceKeys.Shared));

        // Decorated rather than composed in one factory, so this server's policy also reaches a store some other
        // package registered first, and which of them registered it does not decide whether the server's clock skew
        // and log events apply. The tenant's form is outermost, so each tenant reserves in a space of its own.
        services.Decorate<IReplayCache, ConfiguredReplayCache>();
        services.TryAddSingleton<ITenantAccessor, AmbientTenantAccessor>();
        services.Decorate<IReplayCache, TenantReplayCache>();

        return services;
    }

    /// <summary>
    /// <paramref name="registration"/>, an unkeyed registration of the store, as the registration under
    /// <see cref="TenantServiceKeys.Shared"/>, built the same way and kept for as long.
    /// </summary>
    private static ServiceDescriptor AsShared(ServiceDescriptor registration) => registration switch
    {
        { ImplementationInstance: { } instance }
            => ServiceDescriptor.KeyedSingleton(typeof(IReplayCache), TenantServiceKeys.Shared, instance),

        { ImplementationFactory: { } factory }
            => ServiceDescriptor.DescribeKeyed(
                typeof(IReplayCache),
                TenantServiceKeys.Shared,
                (provider, _) => factory(provider),
                registration.Lifetime),

        { ImplementationType: { } type }
            => ServiceDescriptor.DescribeKeyed(
                typeof(IReplayCache), TenantServiceKeys.Shared, type, registration.Lifetime),

        _ => throw new InvalidOperationException(
            $"The registration of {nameof(IReplayCache)} names neither an instance, a factory nor a type."),
    };

    /// <summary>
    /// The record that <see cref="AddReplayPrevention"/> has already run on this collection.
    /// </summary>
    /// <remarks>
    /// A type of its own because the decoration cannot record itself: <c>Decorate</c> registers an
    /// object-typed factory, and a descriptor cannot be asked what a factory will build, so looking
    /// for the decorator finds nothing and the cache is wrapped once per caller. Nothing ever
    /// resolves this; its presence in the collection is the whole signal.
    /// </remarks>
    private sealed class AlreadyRegistered
    {
        /// <summary>The one that gets registered; the container never has to build it.</summary>
        public static readonly AlreadyRegistered Instance = new();
    }
}
