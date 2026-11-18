// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt;

/// <summary>
/// The caches the libraries read when the host registers none: the host's own cache where there is one, an in-process
/// one of the libraries' own where there is not.
/// </summary>
/// <remarks>
/// The in-process caches are never registered under the types a host registers its caches under, only under a key of
/// their own, and the choice is made when a cache is first asked for, so a cache the host registers wins whatever order
/// it is registered in and by whichever method, a <c>TryAdd</c> after the libraries' own registrations included. A
/// <c>TryAdd</c> of the framework's in-memory cache would take the place of that host's cache.
/// Only a cache the host registers without a key is the host's here: one registered only as a keyed service is not
/// found, and the libraries keep their state in process. A host's unkeyed lookups and <c>TryAdd</c> calls see no cache
/// it did not register; a lookup by <c>KeyedService.AnyKey</c> does find the libraries' own.
/// </remarks>
internal static class InProcessCaches
{
    private const string Key = nameof(InProcessCaches);

    /// <summary>
    /// Registers the in-process caches, each built only if a consumer asks for it.
    /// </summary>
    /// <param name="services">The service collection.</param>
    internal static IServiceCollection AddInProcessCaches(this IServiceCollection services)
    {
        services.TryAddKeyedSingleton<IDistributedCache>(
            Key,
            (_, _) => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));
        services.TryAddKeyedSingleton<IMemoryCache>(Key, (_, _) => new MemoryCache(new MemoryCacheOptions()));
        return services;
    }

    /// <summary>
    /// The host's distributed cache, or the in-process one when the host registered none.
    /// </summary>
    /// <param name="serviceProvider">The container the cache is resolved from.</param>
    internal static IDistributedCache DistributedCache(IServiceProvider serviceProvider)
        => serviceProvider.GetService<IDistributedCache>()
           ?? serviceProvider.GetRequiredKeyedService<IDistributedCache>(Key);

    /// <summary>
    /// The host's memory cache, or the in-process one when the host registered none.
    /// </summary>
    /// <param name="serviceProvider">The container the cache is resolved from.</param>
    internal static IMemoryCache MemoryCache(IServiceProvider serviceProvider)
        => serviceProvider.GetService<IMemoryCache>()
           ?? serviceProvider.GetRequiredKeyedService<IMemoryCache>(Key);
}
