// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.Jwt.ReplayPrevention;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt;

/// <summary>
/// Wires the replay cache that remembers the identifiers of single-use tokens already accepted.
/// </summary>
public static class ReplayCacheServiceCollectionExtensions
{
    /// <summary>
    /// The prefix of every entry the registered store writes, whichever package registered it. A stable literal:
    /// entries written under one prefix are unreachable under another, so a rolling upgrade that changed it would
    /// accept, for the length of the retention window, every token the instances still running had refused.
    /// </summary>
    /// <remarks>
    /// The OpenID Connect server writes its own store's entries under it too, so where the server's entity storage is
    /// the shipped one over the same cache, an instance reserving through this store and one reserving through the
    /// server's read each other's reservations.
    /// </remarks>
    internal const string CacheKeyPrefix = "Abblix.Oidc.Server.Features.ReplayPrevention:";

    /// <summary>
    /// Builds the store this method registers; one instance, so the registration it made can be told from any other.
    /// </summary>
    private static readonly Func<IServiceProvider, object> DefaultStore
        = provider => provider.CreateService<DistributedReplayCache>(Dependency.Override(CacheKeyPrefix));

    /// <summary>
    /// Whether <paramref name="registration"/> is the one <see cref="AddDistributedReplayCache"/> made, rather than a
    /// store the host registered itself.
    /// </summary>
    /// <remarks>
    /// The OpenID Connect server puts a store of its own in place of this one and keeps one a host registered. Asked
    /// of the registration rather than of whether this method ran, because a host may register its own store before
    /// a receiver calls this method, which then adds nothing.
    /// </remarks>
    internal static bool IsDefaultStore(ServiceDescriptor registration)
        => registration is { IsKeyedService: false, ImplementationFactory: var factory } && factory == DefaultStore;

    /// <summary>
    /// Registers the replay cache over the host's <c>IDistributedCache</c> as the <see cref="IReplayCache"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The registration of the store made by every receiver of Security Event Tokens or logout tokens, so a host
    /// running several of them shares one store under one prefix. The OpenID Connect server in the same host puts
    /// its store over the host's entity storage in place of this one, whichever of them registers first, and the
    /// receivers reserve there. TryAdd, so a store the host registered before wins.
    /// </para>
    /// <para>
    /// A package with a policy of its own decorates the registered store rather than registering another, so every
    /// package in the host keeps reserving in one store. Beside the OpenID Connect server, a decoration made before
    /// the server registers is kept as the host's own store, and the server reserves in it too.
    /// </para>
    /// <para>
    /// The cache itself is the host's choice and is deliberately not registered here:
    /// <c>AddDistributedMemoryCache()</c> keeps the reservations in one process, Redis or another backend shares
    /// them between instances.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddDistributedReplayCache(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAdd(ServiceDescriptor.Singleton(typeof(IReplayCache), DefaultStore));

        return services;
    }
}
