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
/// Registers the key ring that mints its keys in this process and keeps them there.
/// </summary>
internal static class LocalKeyRingServiceCollectionExtensions
{
    /// <summary>
    /// Registers the ring, refusing a host that registered a store to share keys with.
    /// </summary>
    internal static IServiceCollection AddLocalKeyRing(this IServiceCollection services, LocalKeys policy)
    {
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IKeyRingStore)))
            throw new InvalidOperationException(
                $"{nameof(ExternalKeysServiceCollectionExtensions.AddInMemoryKeyRing)} keeps its keys "
                + "in this process only, but an "
                + $"{nameof(IKeyRingStore)} is registered, which is how keys are shared between processes. "
                + "The store would be ignored. Use "
                + $"{nameof(ExternalKeysServiceCollectionExtensions.AddKeyRing)} with a custodian to share keys, or "
                + "drop the store if a single instance is intended.");

        // Refused here as well as when the ring is made, so a period the ring cannot rotate on stops the host while
        // it registers
        KeyRingPolicyChecks.EnsureRotatable(policy);

        // A ring is registered once, and a later call takes no effect: its policy is not checked against the settings
        // either, or the host would be refused over a policy no ring runs
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IKeyRing)))
            return services;

        // The announcement of a new key is a setting, final only once every configuration has run, so the
        // retention is checked against it when the host starts: the ring itself is made on its first use, which
        // would let the host start and then fail every request for a key
        services.AddOptions<KeyRingOptions>()
            .Validate(
                ring => KeyRingPolicyChecks.IsRetainedThroughAnnouncement(policy, ring.KeyRolloverPropagation),
                KeyRingPolicyChecks.RetainedThroughAnnouncement)
            .ValidateOnStart();

        // The ring reads the clock, and this package is consumable without the registrations that would otherwise
        // have supplied one.
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<IKeyRing>(
            serviceProvider => serviceProvider.CreateService<InMemoryKeyRing>(Dependency.Override(policy)));

        return services;
    }
}
