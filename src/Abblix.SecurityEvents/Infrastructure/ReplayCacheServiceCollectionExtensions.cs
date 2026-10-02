// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Wires the replay cache that remembers the identifiers of tokens already accepted.
/// </summary>
public static class ReplayCacheServiceCollectionExtensions
{
    /// <summary>
    /// Registers the replay cache over the host's <c>IDistributedCache</c> as the
    /// <see cref="IReplayCache"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What it does depends on the path, and the name promises more than one of them delivers. Where a
    /// caller offers a token to be TRUSTED - a DPoP proof, a client assertion, a logout token - the
    /// reservation is read, and a second use of one identifier is refused. On push delivery it is only a
    /// record of what this receiver accepted: <c>PushDeliveryHandler</c> writes after the sink and reads
    /// nothing, because RFC 8935 Section 2 lets a transmitter redeliver and
    /// <see cref="Delivery.ISecurityEventSink"/> answers for that by requiring idempotent processing. Registering
    /// this cache therefore makes deliveries auditable; it does not make a non-idempotent sink safe.
    /// </para>
    /// <para>
    /// The store itself is the host's choice and is deliberately not registered here:
    /// <c>AddDistributedMemoryCache()</c> gives a single-instance receiver process-local
    /// behavior, Redis or another backend gives a scaled-out one a shared memory - the same
    /// registration either way.
    /// </para>
    /// <para>
    /// How long an identifier is remembered comes from the validation profile rather than from
    /// here, because the retention only makes sense against the freshness window it has to
    /// outlive - see <see cref="SecurityEventTokenValidationOptions.ReplayRetention"/>. The
    /// contract itself lives in Abblix.JWT, so a host that also runs the OpenID Connect server
    /// shares one replay store between its DPoP proofs, its client assertions and its events.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddDistributedReplayCache(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IReplayCache>(
            provider => provider.CreateService<DistributedReplayCache>(
                Dependency.Override(CacheKeyPrefix)));

        return services;
    }

    /// <summary>
    /// Keeps these entries out of the way of whatever else shares the host's cache. A stable
    /// literal: entries written under one prefix are unreachable under another, so a rolling
    /// upgrade that changed it would run without replay protection until they aged out.
    /// </summary>
    private const string CacheKeyPrefix = "Abblix.SecurityEvents:ReplayPrevention:";
}
