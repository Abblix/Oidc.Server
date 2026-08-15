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

using Abblix.DependencyInjection;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SharedSignals.Redis;

/// <summary>
/// Wires the Redis-native transmitter storage - the event outbox and the stream registry - into a
/// host's service collection.
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
    /// <param name="options">
    /// What the queue may keep, and for how long; the defaults apply when it is omitted. Registered
    /// with TryAdd, so a host pre-registering its own wins.
    /// </param>
    public static IServiceCollection AddSsfRedisOutbox(
        this IServiceCollection services, RedisOutboxOptions? options = null)
    {
        services.TryAddSingleton(options ?? new RedisOutboxOptions());
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

    /// <summary>
    /// Puts the push delivery claim on Redis, which is what stops several transmitter instances
    /// from delivering one stream's queue to its receiver several times over. A deployment running
    /// more than one instance needs this call: the default claim reaches only inside a process, so
    /// without it every instance believes it holds every stream.
    /// </summary>
    /// <remarks>
    /// Replace for the same reason as its siblings above - it IS the host's explicit choice and
    /// wins in any order relative to the role registration.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSsfRedisDeliveryLease(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<IDeliveryLease, RedisDeliveryLease>());
        return services;
    }

    /// <summary>
    /// Declares the transmitter's stream set as configuration and reconciles it into Redis, so the
    /// half of a stream its RECEIVER owns - the status it set, the subjects it added and removed,
    /// when it last asked for verification - is shared by every instance instead of living in the
    /// memory of whichever one took the request.
    /// </summary>
    /// <remarks>
    /// The file stays the truth about what a stream IS: on startup each declaration is written
    /// over what Redis holds, keeping the receiver's half, and a stream Redis holds that the file
    /// no longer declares is dropped. So editing configuration reaches every instance at its next
    /// start, and a pause reaches them all at once.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="streams">The declared streams.</param>
    public static IServiceCollection AddSsfRedisConfiguredStreams(
        this IServiceCollection services,
        IReadOnlyList<ConfiguredStream> streams)
        => services.AddSsfConfiguredStreams(
            streams, provider => provider.CreateService<RedisStreamStore>());
}
