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
/// Registers the contracts consumers read the key ring by.
/// </summary>
internal static class KeyRingContractsServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="IKeyRings"/> and <see cref="IKeyRing"/> over the one registry of rings.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    public static void AddKeyRingContracts(this IServiceCollection services)
    {
        // Every contract reads the one registry of rings. A ring built anywhere else would be a SECOND ring: the
        // refresh service would keep one current while every consumer read the other, which fails as a server
        // publishing keys it never rotates.
        services.TryAddSingleton<IKeyRings, KeyRings>();
        services.TryAddSingleton<IKeyRing>(serviceProvider =>
            serviceProvider.GetRequiredService<KeyRingRegistry>().Ring(KeyRingOptions.DefaultPartition));
    }
}
