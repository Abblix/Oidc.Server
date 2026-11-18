// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Registers the checks the minted key ring's settings are started with.
/// </summary>
internal static class KeyRingOptionsServiceCollectionExtensions
{
    /// <summary>
    /// Checks at startup that the partitions can name entries in every store and that a store is registered.
    /// </summary>
    internal static IServiceCollection AddKeyRingOptionsChecks(this IServiceCollection services)
    {
        // A partition names its entries in the store, so it must be a name every store accepts, and one the default
        // partition can tell from its own entries
        services.AddOptions<KeyRingOptions>().Validate(
            ring => ring.Partitions.Count > 0 &&
                    ring.Partitions.Distinct(StringComparer.Ordinal).Count() == ring.Partitions.Count &&
                    ring.Partitions.All(KeyRingOptions.IsPartitionName),
            $"{nameof(KeyRingOptions)}.{nameof(KeyRingOptions.Partitions)} must name at least one partition, each " +
            "once, and each of letters, digits, '-', '_' and '~' only: a partition's name goes in front of its " +
            "entries' ids in the store.")

            // The ring needs somewhere to keep its keys, and a builder cannot force the call that supplies it.
            // Checked at startup, because the ring resolves its store only when first asked for, and a container
            // validating itself as it is built does not see that far
            .Validate<IServiceProvider>(
                (_, serviceProvider) => serviceProvider.GetService<IKeyRingStore>() is not null,
                $"The key ring needs an {nameof(IKeyRingStore)} to share the keys it mints, and none is registered. " +
                $"Follow {nameof(ExternalKeysServiceCollectionExtensions.UseKeysInProcess)} or " +
                $"{nameof(ExternalKeysServiceCollectionExtensions.AddKeyRing)} with a PersistRingTo... call from the " +
                $"store's package, or register an {nameof(IKeyRingStore)} of your own.")
            .ValidateOnStart();

        return services;
    }

    /// <summary>
    /// Arms the startup check that the custodian serves the algorithm the ring seals its keys under.
    /// </summary>
    /// <param name="services">The service collection the ring is registered in.</param>
    /// <remarks>
    /// The check reads the builder the ring's setup registers, so it judges the policy the ring runs on rather than
    /// that of a later call no ring follows.
    /// </remarks>
    internal static IServiceCollection AddKeyWrapAlgorithmCheck(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<KeyRingOptions>, KeyWrapAlgorithmCheck>());
        return services;
    }
}
