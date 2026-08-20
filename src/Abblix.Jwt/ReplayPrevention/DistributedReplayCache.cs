// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.Jwt.ReplayPrevention;

/// <summary>
/// A replay cache over the host's <see cref="IDistributedCache"/>: process-local when the host
/// registers the in-memory distributed cache, shared when it registers Redis or another backend -
/// so a scaled-out deployment gains one common memory by swapping the store, not the cache.
/// </summary>
/// <remarks>
/// The add-if-absent underneath is probabilistic, not strict: two concurrent presenters of one
/// identifier can both hear "new" within a single cache round trip, because
/// <see cref="IDistributedCache"/> offers Get and Set and no compare-and-set. Each profile
/// decides whether that is acceptable - RFC 9449 Section 11.1 accepts probabilistic replay
/// defence for DPoP proofs, and RFC 8935 Section 2 lets a transmitter redeliver a SET regardless,
/// so a lost race costs one duplicate idempotent pass. A client assertion is the one that does not
/// read that way, since RFC 7523 Section 3 lets an authorization server reject a reused one. A
/// deployment relying on that rejection takes a <see cref="ReplayCacheBase"/> over a store
/// that decides and writes in one operation.
/// </remarks>
/// <param name="cache">The distributed cache the host registered; the store is the host's choice.
/// </param>
/// <param name="clock">The clock the retention window is measured against.</param>
/// <param name="keyPrefix">
/// Keeps these entries out of the way of whatever else shares the host's cache. It is the
/// caller's to choose and its exact text is a deployment contract, not an implementation detail:
/// entries written under one prefix are invisible under another, so changing it mid-rollout
/// leaves the identifiers already reserved unreachable until they age out.</param>
public sealed class DistributedReplayCache(
    IDistributedCache cache,
    TimeProvider clock,
    string keyPrefix) : ReplayCacheBase(clock, keyPrefix)
{
    /// <inheritdoc />
    /// <remarks>
    /// This is the implementation that cannot keep the base class's one demand, and it is here
    /// rather than in a strict sibling precisely because <see cref="IDistributedCache"/> offers Get
    /// and Set and nothing that decides. The helper below is add-if-absent by intent and
    /// read-then-write by construction, which is what makes this cache probabilistic - see the
    /// class remarks for which profiles accept that and which do not.
    /// </remarks>
    protected override Task<bool> ReserveIfAbsentAsync(
        string key,
        TimeSpan timeToLive,
        CancellationToken cancellationToken)
        => cache.TryAddAsync(key, timeToLive, cancellationToken);
}
