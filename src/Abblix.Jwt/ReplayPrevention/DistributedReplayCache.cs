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
/// deployment relying on that rejection takes <c>Abblix.JWT.Redis</c>, whose reservation the server
/// decides inside the command that writes it.
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
    string keyPrefix) : IReplayCache
{
    private readonly string _keyPrefix = keyPrefix ?? throw new ArgumentNullException(nameof(keyPrefix));

    /// <inheritdoc />
    public async Task<bool> TryReserveAsync(
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        // A time-to-live rather than an absolute moment, because that is what the cache takes.
        // The shared primitive floors a value already in the past, so an expiry that has just
        // elapsed still records the sighting instead of silently reserving nothing.
        return await cache.TryAddAsync(
            _keyPrefix + identifier,
            expiresAt - clock.GetUtcNow(),
            cancellationToken);
    }
}
