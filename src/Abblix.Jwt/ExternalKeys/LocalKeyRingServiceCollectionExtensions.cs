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

        // The ring reads the clock, and this package is consumable without the registrations that would otherwise
        // have supplied one.
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<IKeyRing>(
            serviceProvider => serviceProvider.CreateService<InMemoryKeyRing>(Dependency.Override(policy)));

        return services;
    }
}
