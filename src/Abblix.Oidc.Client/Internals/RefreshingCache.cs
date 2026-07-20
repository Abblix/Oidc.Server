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
    /// The in-flight or completed fetch together with its expiry, held as a single reference so a reader
    /// observes both from the same attempt rather than a mix of two.
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
        var observed = Volatile.Read(ref _entry);
        if (!forceRefresh && IsValid(observed))
            return await observed!.Fetch.WaitAsync(cancellationToken);

        // The observed entry is missing, aged out, or explicitly rejected, so a fetch is owed. Publishing the
        // replacement before the fetch runs is what makes callers share it: a caller arriving mid-flight
        // finds this entry and awaits the same attempt instead of starting its own.
        //
        // The fetch itself is started without any one caller's cancellation token. It is shared, so letting
        // the first caller's cancellation abort it would cancel everyone else's read as a side effect. Each
        // caller instead abandons its own wait below.
        var replacement = new Entry(() => fetch(CancellationToken.None), _timeProvider.GetUtcNow() + Jitter(lifetime));

        // Whoever wins the exchange owns the fetch; whoever loses joins the winner's rather than duplicating
        // it. Comparing against the entry this caller actually observed is what makes a forced refresh accept
        // a replacement someone else has already published.
        var current = Interlocked.CompareExchange(ref _entry, replacement, observed);
        var winner = ReferenceEquals(current, observed) ? replacement : current!;

        try
        {
            return await winner.Fetch.WaitAsync(cancellationToken);
        }
        catch when (!cancellationToken.IsCancellationRequested)
        {
            // A failed attempt must not be left in place, or one unlucky moment silences the provider for the
            // rest of the lifetime. Removed only if it is still the entry held, so a retry that has already
            // succeeded is not thrown away.
            Interlocked.CompareExchange(ref _entry, null, winner);
            throw;
        }
    }

    /// <summary>
    /// Shortens a lifetime by a random share of itself, so replicas started together stop expiring together.
    /// </summary>
    private static TimeSpan Jitter(TimeSpan lifetime)
        => lifetime - lifetime * (Random.Shared.NextDouble() * MaximumJitterShare);

    private bool IsValid(Entry? entry) => entry is not null && _timeProvider.GetUtcNow() < entry.ExpiresAt;

    /// <summary>
    /// One attempt to read the value, shared by every caller that arrives while it is in flight.
    /// </summary>
    /// <remarks>
    /// The fetch is started lazily and exactly once, so an entry that loses the exchange never runs the
    /// request it was created for.
    ///
    /// The lifetime is measured from when the attempt started rather than from when it finished, which errs
    /// towards reading again sooner.
    /// </remarks>
    private sealed class Entry
    {
        private readonly Lazy<Task<T>> _fetch;

        public Entry(Func<Task<T>> fetch, DateTimeOffset expiresAt)
        {
            _fetch = new Lazy<Task<T>>(fetch, LazyThreadSafetyMode.ExecutionAndPublication);
            ExpiresAt = expiresAt;
        }

        public Task<T> Fetch => _fetch.Value;

        public DateTimeOffset ExpiresAt { get; }
    }
}
