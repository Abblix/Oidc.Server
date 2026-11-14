// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;

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
    internal static IServiceCollection AddKeyRingParts(this IServiceCollection services, MintedKeysBuilder builder)
        => services
            .AddKeyRingSetup(builder)
            .AddKeyRingSteps()
            .AddKeyRingContracts();
}
