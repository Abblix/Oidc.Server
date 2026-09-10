// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Redis;

/// <summary>
/// Registers the Redis-backed take-once redemption.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Lets Redis decide who redeems a stored authorization, so a provider running as several instances
    /// hands each authorization code, device code and CIBA request id to exactly one caller.
    /// </summary>
    /// <remarks>
    /// Without this the server serializes redemptions of one key inside a single process, which is the
    /// whole answer for one instance and no answer at all for several.
    /// <para>
    /// The connection is the host's: register an <c>IConnectionMultiplexer</c> alongside this, which a
    /// deployment already using Redis for its distributed cache has.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection to register into.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddRedisTakeOnceStore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // TryAdd, so a host that brought its own implementation of the seam keeps it.
        services.TryAddSingleton<ITakeOnceStore, RedisTakeOnceStore>();
        return services;
    }
}
