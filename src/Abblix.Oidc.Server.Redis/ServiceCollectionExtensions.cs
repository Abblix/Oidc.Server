// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Redis;

/// <summary>
/// Registers the Redis-backed entity storage.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Puts the server's short-lived entities in Redis, so a provider running as several instances
    /// hands each authorization code, device code and CIBA request id to exactly one caller.
    /// </summary>
    /// <remarks>
    /// Without this the server serializes redemptions of one key inside a single process, which is the
    /// whole answer for one instance and no answer at all for several.
    /// <para>
    /// The connection is the host's: register an <c>IConnectionMultiplexer</c> alongside this, which a
    /// deployment already using Redis has.
    /// </para>
    /// <para>
    /// Replace rather than TryAdd, and the difference is not stylistic: the server registers its own
    /// storage with TryAdd, so a TryAdd here would silently lose whenever this call came second, and
    /// the losing arrangement is the one that reads as configured and stores nowhere. Calling this IS
    /// the host's explicit choice, so it wins in either order.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <param name="options">Where in Redis the entries are written. The defaults suit a Redis this
    /// deployment does not share.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddRedisEntityStorage(
        this IServiceCollection services,
        RedisEntityStorageOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // TryAdd, because a host's own registration wins over anything a library extension does - and
        // that leaves one way to lose a choice silently: options handed to this call while a different
        // instance is already registered. The prefix decides WHERE records live, so losing it writes
        // authorizations under one name and looks for them under another, and every holder is told the
        // code expired. Neither instance may be discarded, so the contradiction is refused at startup
        // rather than settled by whichever call happened to run first.
        if (options is not null)
        {
            var registered = services
                .FirstOrDefault(descriptor => descriptor.ServiceType == typeof(RedisEntityStorageOptions))
                ?.ImplementationInstance;

            if (registered is not null && !ReferenceEquals(registered, options))
            {
                throw new InvalidOperationException(
                    $"A different {nameof(RedisEntityStorageOptions)} is already registered, and these "
                    + "name different places for the same records. Pass them once, or register them and "
                    + $"call {nameof(AddRedisEntityStorage)} with none.");
            }
        }

        services.TryAddSingleton(options ?? new RedisEntityStorageOptions());

        services.Replace(ServiceDescriptor.Singleton<IEntityStorage, RedisEntityStorage>());
        return services;
    }
}
