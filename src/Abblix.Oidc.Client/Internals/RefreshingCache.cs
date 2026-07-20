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

namespace Abblix.Oidc.Client.Internals;

/// <summary>
/// Holds a value fetched from the provider and re-fetches it once it has aged out.
/// </summary>
/// <typeparam name="T">The cached value.</typeparam>
/// <remarks>
/// The client reads two things from the provider that change rarely and cost a round trip: the discovery
/// document and the key set. Both want the same behaviour, so it lives here once.
///
/// Two properties matter and are easy to get wrong separately: concurrent first calls must produce one round
/// trip rather than a stampede, and a failed fetch must not be cached, or one unlucky moment silences the
/// provider for the whole lifetime.
/// </remarks>
internal sealed class RefreshingCache<T>
    where T : class
{
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Serializes fetches so concurrent callers share one round trip.
    /// </summary>
    private readonly SemaphoreSlim _fetchGate = new(1, 1);

    /// <summary>
    /// The value together with its expiry, held as a single reference so a reader outside the gate observes
    /// both from the same fetch rather than a mix of two.
    /// </summary>
    private Entry? _entry;

    /// <summary>
    /// The largest share of a lifetime that may be cut from it to spread expiry across instances.
    /// </summary>
    /// <remarks>
    /// Replicas of the same deployment start together, so without this their entries expire within
    /// milliseconds of each other and every replica goes to the provider in one wave. Cutting a random slice
    /// off each lifetime pulls them apart.
    ///
    /// The slice is only ever subtracted, never added: a value is then held no longer than the configured
    /// lifetime, so the jitter cannot extend how long a stale document or key set stays in use.
    /// </remarks>
    private const double MaximumJitterShare = 0.1;

    /// <summary>
    /// Creates the cache over the clock that decides when an entry has aged out.
    /// </summary>
    public RefreshingCache(TimeProvider timeProvider) => _timeProvider = timeProvider;

    /// <summary>
    /// Returns the held value, fetching it when nothing valid is held.
    /// </summary>
    /// <param name="fetch">Reads the value from the provider.</param>
    /// <param name="lifetime">How long a fetched value stays valid.</param>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    public Task<T> GetAsync(
        Func<CancellationToken, Task<T>> fetch, TimeSpan lifetime, CancellationToken cancellationToken)
        => GetAsync(fetch, lifetime, forceRefresh: false, cancellationToken);

    /// <summary>
    /// Returns the held value, optionally discarding a still-valid one first.
    /// </summary>
    /// <param name="fetch">Reads the value from the provider.</param>
    /// <param name="lifetime">How long a fetched value stays valid.</param>
    /// <param name="forceRefresh">Fetches even when the held value has not aged out.</param>
    /// <param name="cancellationToken">Cancels the fetch.</param>
    public async Task<T> GetAsync(
        Func<CancellationToken, Task<T>> fetch,
        TimeSpan lifetime,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        T value;
        if (!forceRefresh && TryReadValid(out value))
            return value;

        // Captured before waiting, so that after the gate this caller can tell whether the entry it found
        // wanting is still the one held. A timestamp cannot answer that: a clock too coarse to separate two
        // adjacent operations would make a forced refresh accept the very entry it was asked to replace.
        var rejectedEntry = _entry;

        await _fetchGate.WaitAsync(cancellationToken);
        try
        {
            // Another caller may have fetched while this one waited on the gate, in which case its result
            // stands and this caller does not repeat the round trip.
            if (!ReferenceEquals(_entry, rejectedEntry) && TryReadValid(out value))
                return value;

            var fetched = await fetch(cancellationToken);

            // Assigned only on success, so a transient failure does not silence the provider for the rest of
            // the lifetime.
            _entry = new Entry(fetched, _timeProvider.GetUtcNow() + Jitter(lifetime));
            return fetched;
        }
        finally
        {
            _fetchGate.Release();
        }
    }

    /// <summary>
    /// Shortens a lifetime by a random share of itself, so replicas started together stop expiring together.
    /// </summary>
    private static TimeSpan Jitter(TimeSpan lifetime)
        => lifetime - lifetime * (Random.Shared.NextDouble() * MaximumJitterShare);

    private bool TryReadValid(out T value)
    {
        var entry = _entry;
        if (entry is not null && _timeProvider.GetUtcNow() < entry.ExpiresAt)
        {
            value = entry.Value;
            return true;
        }

        value = null!;
        return false;
    }

    private sealed record Entry(T Value, DateTimeOffset ExpiresAt);
}
