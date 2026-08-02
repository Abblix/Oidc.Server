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

using System.Collections.Concurrent;
using Abblix.SecurityEvents.Abstractions;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// A process-local replay cache over a sliding window of the tokens' issue times. Right for a
/// single-instance receiver; a scaled-out one needs a shared store behind the same interface,
/// which stays application code or a separate package by the plan's boundary.
/// </summary>
/// <remarks>
/// Eviction leans on the validation window: a token whose "iat" is older than the receiver's
/// tolerance never reaches the cache, because the freshness step rejected it first. Entries older
/// than the retention are therefore unreachable and safe to drop - which is why the retention
/// must be at least the validation tolerance, and the constructor refuses a zero or negative one
/// outright.
/// </remarks>
/// <param name="clock">The receiver's clock.</param>
/// <param name="retention">
/// How long an identifier is remembered past its token's issue time. Must cover the validation
/// profile's issued-at tolerance with a margin - an entry evicted while its token still passes
/// freshness would let that token replay.</param>
public sealed class InMemoryJtiReplayCache(TimeProvider clock, TimeSpan retention) : IJtiReplayCache
{
    private readonly ConcurrentDictionary<(string Issuer, string JwtId), DateTimeOffset> _entries = new();

    private readonly TimeSpan _retention = retention > TimeSpan.Zero
        ? retention
        : throw new ArgumentOutOfRangeException(
            nameof(retention),
            retention,
            "A replay cache remembering nothing detects nothing.");

    /// <summary>
    /// How often at most a registration pays for a full sweep of the entries: eviction amortized
    /// so the hot path stays O(1) between sweeps.
    /// </summary>
    private static readonly TimeSpan EvictionInterval = TimeSpan.FromMinutes(1);

    private long _nextEvictionTicks = clock.GetUtcNow().Add(EvictionInterval).UtcTicks;

    /// <inheritdoc />
    public ValueTask<bool> TryRegisterAsync(
        string issuer,
        string jwtId,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        EvictExpired();

        return ValueTask.FromResult(_entries.TryAdd((issuer, jwtId), issuedAt));
    }

    private void EvictExpired()
    {
        var now = clock.GetUtcNow();
        var nextEviction = Interlocked.Read(ref _nextEvictionTicks);

        if (now.UtcTicks < nextEviction)
        {
            return;
        }

        // One caller wins the sweep; the rest continue registering. Losing the race costs
        // nothing - the winner is already removing the same expired entries.
        if (Interlocked.CompareExchange(
                ref _nextEvictionTicks,
                now.Add(EvictionInterval).UtcTicks,
                nextEviction) != nextEviction)
        {
            return;
        }

        var horizon = now - _retention;
        foreach (var (key, issuedAt) in _entries)
        {
            if (issuedAt < horizon)
            {
                _entries.TryRemove(key, out _);
            }
        }
    }
}
