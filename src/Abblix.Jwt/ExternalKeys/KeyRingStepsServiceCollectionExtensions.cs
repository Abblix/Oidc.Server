// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Registers what the key ring does with its partitions: opening them, removing their entries, checking the ring at
/// startup and starting its refresh rounds.
/// </summary>
internal static class KeyRingStepsServiceCollectionExtensions
{
    /// <summary>
    /// Registers the steps the key ring takes over its partitions.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    internal static IServiceCollection AddKeyRingSteps(this IServiceCollection services)
    {
        services.TryAddSingleton<KeyRingPartitionOpening>();
        services.TryAddSingleton<KeyRingPartitionsOpening>();
        services.TryAddSingleton<KeyRingEntriesRemoval>();
        services.TryAddSingleton<KeyRingStartupCheck>();
        services.TryAddSingleton<KeyRingRounds>();
        return services;
    }
}
