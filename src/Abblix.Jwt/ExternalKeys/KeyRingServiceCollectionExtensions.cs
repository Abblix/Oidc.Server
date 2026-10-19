// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Registers the parts the key ring is composed of.
/// </summary>
internal static class KeyRingServiceCollectionExtensions
{
    /// <summary>
    /// Registers the parts of the key ring <paramref name="builder"/> sets up, and the contracts consumers read it
    /// by.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="builder">The builder holding the ring's policy.</param>
    public static void AddKeyRingParts(this IServiceCollection services, MintedKeysBuilder builder)
    {
        // A factory, unlike the plain registrations around it, because the policy is a per-call value the container
        // knows nothing about: every part of the ring takes it from here and everything else is resolved normally.
        // It is read off the builder rather than captured, so a call chained after AddKeyRing - AdoptExistingKeys -
        // still reaches the ring: this factory runs when the ring is first asked for, by which time the whole chain
        // has run. The partitions are the host's when it registered any, whichever side of AddKeyRing it did, and
        // the settings' otherwise. The store is resolved here too, and only here, so a container validating itself
        // as it is built leaves a missing store to the startup validation AddKeyRing registers.
        services.TryAddSingleton(
            serviceProvider => new KeyRingSetup(
                builder.Policy,
                serviceProvider.GetService<IKeyRingPartitions>() ??
                serviceProvider.CreateService<OptionsKeyRingPartitions>(),
                serviceProvider.GetRequiredService<IKeyRingStore>()));

        services.TryAddSingleton(
            serviceProvider =>
            {
                var setup = serviceProvider.GetRequiredService<KeyRingSetup>();
                return new KeyRingFactory(serviceProvider, setup.Policy, setup.Store);
            });

        services.TryAddSingleton<KeyRingRegistry>();
        services.TryAddSingleton<KeyRingPartitionOpening>();
        services.TryAddSingleton<KeyRingPartitionsOpening>();
        services.TryAddSingleton<KeyRingEntriesRemoval>();
        services.TryAddSingleton<KeyRingStartupCheck>();
        services.TryAddSingleton<KeyRingRounds>();

        // Every contract reads the one registry of rings. A ring built anywhere else would be a SECOND ring: the
        // refresh service would keep one current while every consumer read the other, which fails as a server
        // publishing keys it never rotates.
        services.TryAddSingleton<IKeyRings, KeyRings>();
        services.TryAddSingleton<IKeyRing>(serviceProvider =>
            serviceProvider.GetRequiredService<KeyRingRegistry>().Ring(KeyRingOptions.DefaultPartition));
    }
}
