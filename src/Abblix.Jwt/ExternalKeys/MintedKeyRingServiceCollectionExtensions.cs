// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Registers the key ring that mints its keys, seals them to the custodian and shares them through a store.
/// </summary>
internal static class MintedKeyRingServiceCollectionExtensions
{
    /// <summary>
    /// Registers the ring, its refresh service and the checks it is started with.
    /// </summary>
    /// <returns>A builder for the call that supplies the store.</returns>
    internal static IMintedKeysBuilder AddMintedKeyRing(this IServiceCollection services, MintedKeys policy)
    {
        KeyRingPolicyChecks.EnsureRotatable(policy);
        services.TryAddSingleton<KeyEnvelope>();

        // Both the ring and the loop that keeps it current read the clock, and this package is consumable without
        // the registrations that would otherwise have supplied one. TryAdd, so a host's own clock still wins.
        services.TryAddSingleton(TimeProvider.System);

        var builder = new MintedKeysBuilder(services, policy);
        services.AddKeyRingParts(builder);

        services.AddKeyRingOptionsChecks();

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, KeyRingRefreshService>());

        return builder;
    }
}
