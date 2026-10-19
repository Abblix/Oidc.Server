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
/// Registers what the key ring is set up with and the registry of its rings.
/// </summary>
internal static class KeyRingSetupServiceCollectionExtensions
{
    /// <summary>
    /// Registers the setup of the key ring <paramref name="builder"/> holds the policy of, the factory of its rings
    /// and the registry holding them.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="builder">The builder holding the ring's policy.</param>
    internal static IServiceCollection AddKeyRingSetup(this IServiceCollection services, MintedKeysBuilder builder)
    {
        // A factory, unlike the plain registrations around it, because the policy is a per-call value the container
        // knows nothing about: every part of the ring takes it from here and everything else is resolved normally.
        // It is read off the builder rather than captured, so a call chained after AddKeyRing - AdoptExistingKeys -
        // still reaches the ring: this factory runs when the ring is first asked for, by which time the whole chain
        // has run. The partitions are the host's when it registered any, whichever side of AddKeyRing it did, and
        // the settings' otherwise. The store is resolved here too, and only here, so a container validating itself
        // as it is built leaves a missing store to the startup validation AddKeyRing registers.
        // The builder of the first registration is the one the ring runs on, and the one every check of its policy
        // reads, since both take it from here
        services.TryAddSingleton(builder);
        services.TryAddSingleton(
            serviceProvider => new KeyRingSetup(
                serviceProvider.GetRequiredService<MintedKeysBuilder>().Policy,
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
        return services;
    }
}
