// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SharedSignals.Redis;

/// <summary>
/// Wires the Redis-native outbox into a host's service collection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Puts the transmitter's outbox on Redis's own structures - the choice for a transmitter
    /// that scales beyond one replica, where a whole-queue-as-one-value outbox loses concurrent
    /// mutations. The host registers its <c>IConnectionMultiplexer</c>; this call, like its
    /// distributed-cache sibling, uses Replace so the explicit choice wins in any order
    /// relative to the role registration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSsfRedisOutbox(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<IEventOutbox, RedisEventOutbox>());
        return services;
    }

    /// <summary>
    /// Puts the transmitter's stream registrations on one Redis hash - the durable store for a
    /// transmitter whose streams must outlive its process without a database of its own. The host
    /// registers its <c>IConnectionMultiplexer</c>; this call uses Replace for the same reason as the
    /// outbox above: it IS the host's explicit choice of store and wins in any registration order.
    /// </summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSsfRedisStreamStore(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<IStreamStore, RedisStreamStore>());
        return services;
    }
}
