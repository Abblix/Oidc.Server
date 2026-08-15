// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.DependencyInjection;
using Abblix.Jwt.ReplayPrevention;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt.Redis;

/// <summary>
/// Wires the Redis-native replay cache into a host's service collection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// The namespace reservations live under when the caller names none. Stable by design: entries
    /// written under one prefix are invisible under another, so a value that moved between versions
    /// would leave a rollout unable to see what the instances it replaces reserved.
    /// </summary>
    public const string DefaultKeyPrefix = $"{nameof(Abblix)}.{nameof(Jwt)}:{nameof(ReplayPrevention)}:";

    /// <summary>
    /// Registers the strict replay cache: every reservation is one conditional write decided by
    /// the Redis server, so concurrent presenters of a single-use token are separated no matter
    /// how many instances of the application are running.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Replace rather than TryAdd, because this call IS the host's explicit choice of
    /// implementation and must win whether it runs before or after whichever registration supplies
    /// the distributed-cache default - <c>AddOidcCore</c>, <c>AddSecurityEvents</c> and the Shared
    /// Signals roles each offer one, and they are alternatives rather than co-existing namespaces:
    /// the contract is singular, so exactly one implementation serves DPoP proofs, client
    /// assertions and Security Event Tokens alike. That is safe because a profile whose identifier
    /// is unique only within a scope composes the scope into the value it reserves.
    /// </para>
    /// <para>
    /// The host registers its own <c>IConnectionMultiplexer</c>; opening and configuring the
    /// connection is a deployment decision, not this package's.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="keyPrefix">
    /// The namespace reservations live under; <see cref="DefaultKeyPrefix"/> when omitted. Name it
    /// explicitly to place the entries beside something else in the same Redis, and treat the value
    /// as a deployment contract afterwards: changing it leaves what the previous instances reserved
    /// unreachable, so a token they refused passes as fresh until the old entries age out.</param>
    public static IServiceCollection AddRedisReplayCache(
        this IServiceCollection services,
        string? keyPrefix = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // The clock is this cache's own dependency, so the registration supplies it: a host takes
        // this package without necessarily taking whichever other registration would have.
        services.TryAddSingleton(TimeProvider.System);

        services.Replace(ServiceDescriptor.Singleton<IReplayCache>(provider =>
            provider.CreateService<RedisReplayCache>(
                Dependency.Override(keyPrefix ?? DefaultKeyPrefix))));

        return services;
    }
}
