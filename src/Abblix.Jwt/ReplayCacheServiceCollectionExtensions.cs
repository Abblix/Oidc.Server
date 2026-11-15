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
    private const string CacheKeyPrefix = "Abblix.Oidc.Server.Features.ReplayPrevention:";

    /// <summary>
    /// Registers the replay cache over the host's <c>IDistributedCache</c> as the <see cref="IReplayCache"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The one registration of the store, made by every package that reserves identifiers - a receiver of
    /// Security Event Tokens or logout tokens, and the OpenID Connect server for its client assertions, DPoP proofs
    /// and bearer grants - so a host running several of them shares one store under one prefix, whichever of them
    /// it registers first. A package with a policy of its own decorates this store rather than registering
    /// another. TryAdd, so a store the host registered before wins.
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
        services.TryAddSingleton<IReplayCache>(
            provider => provider.CreateService<DistributedReplayCache>(Dependency.Override(CacheKeyPrefix)));

        return services;
    }
}
