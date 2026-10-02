// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SharedSignals.Infrastructure;

/// <summary>
/// Replaces where the transmitter keeps its streams and its outbox. Each call is the host's explicit
/// choice, so it wins over the in-memory defaults in whichever order the two run.
/// </summary>
public static class StreamStorageServiceCollectionExtensions
{
    /// <summary>
    /// Declares the transmitter's stream set as configuration: the store of a closed
    /// deployment whose receivers are the operator's own products - nothing to back up,
    /// lifecycle in the operator's file, API mutations ephemeral until restart.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Replace rather than TryAdd, deliberately: this call IS the host's explicit choice of
    /// store, so it wins whether it runs before or after
    /// <see cref="TransmitterServiceCollectionExtensions.AddSharedSignalsTransmitter"/>'s in-memory default.
    /// </para>
    /// <para>
    /// The declarations are reconciled into a backing store, and this overload's is in memory -
    /// right for one instance, and the reason a receiver's pause reaches no further than the
    /// instance that took the request. A transmitter running several passes a shared one, which
    /// <c>AddSharedSignalsRedisConfiguredStreams</c> does.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="streams">The declared streams.</param>
    public static IServiceCollection AddSharedSignalsConfiguredStreams(
        this IServiceCollection services,
        IReadOnlyList<ConfiguredStream> streams)
        => services.AddSharedSignalsConfiguredStreams(streams, _ => new InMemoryStreamStore());

    /// <summary>
    /// Declares the transmitter's stream set as configuration, reconciled into a backing store the
    /// caller chooses - the form a deployment running more than one instance takes, so that the
    /// half of a stream its receiver owns is shared rather than per-instance.
    /// </summary>
    /// <remarks>
    /// The backing store is built by a factory rather than resolved from the container, because
    /// the container's <see cref="IStreamStore"/> is what this call registers: resolving it would
    /// hand the store itself.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="streams">The declared streams.</param>
    /// <param name="backingStore">Builds the store the declarations are reconciled into.</param>
    public static IServiceCollection AddSharedSignalsConfiguredStreams(
        this IServiceCollection services,
        IReadOnlyList<ConfiguredStream> streams,
        Func<IServiceProvider, IStreamStore> backingStore)
    {
        ArgumentNullException.ThrowIfNull(streams);
        ArgumentNullException.ThrowIfNull(backingStore);

        services.Replace(ServiceDescriptor.Singleton<IStreamStore>(provider =>
            provider.CreateService<ConfigurationStreamStore>(
                Dependency.Override(streams),
                Dependency.Override(backingStore(provider)))));

        return services;
    }

    /// <summary>
    /// Puts the transmitter's outbox on the host's <c>IDistributedCache</c>, so pending events
    /// survive a process restart when the store behind the cache does. Replace rather than
    /// TryAdd for the same reason as
    /// <see cref="AddSharedSignalsConfiguredStreams(IServiceCollection, IReadOnlyList{ConfiguredStream})"/>:
    /// an explicit choice wins in any order.
    /// </summary>
    /// <remarks>
    /// Surviving a restart and surviving a second instance are different properties, and this call
    /// buys the first only. <c>IDistributedCache</c> writes whole values with no compare-and-set,
    /// so two instances editing one stream's queue overwrite each other; a transmitter running
    /// more than one instance takes <c>AddSharedSignalsRedisOutbox</c> instead.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSharedSignalsDistributedOutbox(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<IEventOutbox, DistributedCacheEventOutbox>());
        return services;
    }
}
