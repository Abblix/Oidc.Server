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

using Abblix.SecurityEvents.Abstractions;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// A replay cache over the host's <see cref="IDistributedCache"/>: process-local when the host
/// registers the in-memory distributed cache, shared when it registers Redis or another backend -
/// so a scaled-out receiver gets one feed-wide memory by swapping the store, not the cache.
/// </summary>
/// <remarks>
/// <para>
/// Eviction leans on the validation window: a token whose "iat" is older than the receiver's
/// tolerance never reaches the cache, because the freshness step rejected it first. An entry is
/// therefore stored until its token's issue time plus the retention, after which the identifier
/// is unreachable and safe to forget - which is why the retention must be at least the validation
/// tolerance, and the constructor refuses a zero or negative one outright.
/// </para>
/// <para>
/// The underlying add-if-absent is probabilistic, not strict: two concurrent deliveries of the
/// same SET can both hear "new" within one cache round-trip. That is acceptable here by contract -
/// RFC 8935 Section 2 lets a transmitter deliver the same SET again regardless of earlier
/// responses, so a receiver processes events idempotently and a lost race costs a duplicate
/// idempotent pass, never a security failure. A host needing strict exactly-once plugs a
/// backend-aware implementation behind the same interface.
/// </para>
/// </remarks>
/// <param name="cache">The distributed cache the host registered; the store is the host's choice.
/// </param>
/// <param name="clock">The receiver's clock.</param>
/// <param name="retention">
/// How long an identifier is remembered past its token's issue time. Must cover the validation
/// profile's issued-at tolerance with a margin - an entry evicted while its token still passes
/// freshness would let that token replay.</param>
public sealed class DistributedJtiReplayCache(
    IDistributedCache cache,
    TimeProvider clock,
    TimeSpan retention) : IJtiReplayCache
{
    /// <summary>
    /// Keeps the entries out of the way of whatever else shares the host's cache. Derived from
    /// the type's own name, so it follows a rename; entries orphaned by such a rename age out
    /// within the retention and cost at most one duplicate idempotent pass.
    /// </summary>
    private const string CacheKeyPrefix =
        $"{nameof(Abblix)}.{nameof(SecurityEvents)}:{nameof(DistributedJtiReplayCache)}:";

    private readonly TimeSpan _retention = retention <= TimeSpan.Zero
        ? throw new ArgumentOutOfRangeException(nameof(retention), retention, "A replay cache remembering nothing detects nothing.")
        : retention;

    /// <inheritdoc />
    public async Task<bool> TryRegisterAsync(
        string issuer,
        string jwtId,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        // Escaping removes ':' from both parts, so the separator is unambiguous and distinct
        // (issuer, jti) pairs cannot collide onto one key - the pair is the key because "jti" is
        // unique only "within a particular event feed" (RFC 8417 Section 2.2).
        var cacheKey = $"{CacheKeyPrefix}{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(jwtId)}";

        return await cache.TryAddAsync(cacheKey, issuedAt + _retention - clock.GetUtcNow(), cancellationToken);
    }
}
