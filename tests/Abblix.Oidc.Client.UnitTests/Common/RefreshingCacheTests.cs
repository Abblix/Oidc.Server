// Abblix OIDC Client Library
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

using Abblix.Oidc.Client.Common;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Common;

/// <summary>
/// Tests for <see cref="RefreshingCache{T}"/>, the primitive that keeps the client from asking the provider
/// the same question twice at once.
/// </summary>
public class RefreshingCacheTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    // Every Fetch below names its cancellation token '_', because the cache deliberately never passes a
    // caller's token into the fetch: the attempt is shared, so honouring one caller's cancellation would
    // abort the read the other nineteen are waiting on. That is the property
    // OneCallerCancellingDoesNotCancelTheOthers exists to pin, and the discard says the parameter is
    // ignored on purpose rather than by oversight.

    /// <summary>
    /// Callers that arrive while a read is in flight share it rather than each starting their own. This is
    /// the property the whole class exists for: without it, a burst of requests on a cold instance becomes a
    /// burst of identical requests against the provider.
    /// </summary>
    [Fact]
    public async Task ConcurrentCallersShareOneFetch()
    {
        var fetchCount = 0;
        var release = new TaskCompletionSource();

        var cache = new RefreshingCache<string>(new FakeTimeProvider());

        // Started while the fetch is deliberately held open, so every caller is in flight at once.
        var callers = Enumerable
            .Range(0, 20)
            .Select(_ => cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken))
            .ToArray();

        release.SetResult();
        var results = await Task.WhenAll(callers);

        Assert.Equal(1, fetchCount);
        Assert.All(results, result => Assert.Equal("value", result));

        async Task<string> Fetch(CancellationToken _)
        {
            Interlocked.Increment(ref fetchCount);
            await release.Task;
            return "value";
        }
    }

    /// <summary>
    /// A failing read is shared too, so an unreachable provider is asked once per burst rather than once per
    /// caller. Amplifying load against a provider that is already struggling is exactly the wrong response.
    /// </summary>
    [Fact]
    public async Task ConcurrentCallersShareOneFailedFetch()
    {
        var fetchCount = 0;
        var release = new TaskCompletionSource();

        var cache = new RefreshingCache<string>(new FakeTimeProvider());

        async Task<string> Fetch(CancellationToken _)
        {
            Interlocked.Increment(ref fetchCount);
            await release.Task;
            throw new InvalidOperationException("the provider is unreachable");
        }

        var callers = Enumerable
            .Range(0, 10)
            .Select(_ => cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken))
            .ToArray();

        release.SetResult();

        foreach (var caller in callers)
            await Assert.ThrowsAsync<InvalidOperationException>(() => caller);

        Assert.Equal(1, fetchCount);
    }

    /// <summary>
    /// A failure is not held: the next caller tries again rather than being told for the rest of the lifetime
    /// what one unlucky moment found.
    /// </summary>
    [Fact]
    public async Task AFailedFetchIsNotHeld()
    {
        var attempt = 0;
        var cache = new RefreshingCache<string>(new FakeTimeProvider());

        Task<string> Fetch(CancellationToken _) => ++attempt == 1
            ? Task.FromException<string>(new InvalidOperationException("transient"))
            : Task.FromResult("value");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken));

        Assert.Equal("value", await cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// One caller giving up does not cancel the read the others are waiting on, which is the hazard that
    /// comes with sharing an attempt.
    /// </summary>
    [Fact]
    public async Task OneCallerCancellingDoesNotCancelTheOthers()
    {
        var release = new TaskCompletionSource();
        var cache = new RefreshingCache<string>(new FakeTimeProvider());

        async Task<string> Fetch(CancellationToken _)
        {
            await release.Task;
            return "value";
        }

        using var impatient = new CancellationTokenSource();
        var abandoned = cache.GetAsync(Fetch, Lifetime, impatient.Token);
        var patient = cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken);

        await impatient.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => abandoned);

        release.SetResult();
        Assert.Equal("value", await patient);
    }

    /// <summary>
    /// Once the value has aged out it is read again.
    /// </summary>
    [Fact]
    public async Task ReadsAgainOnceTheLifetimeHasElapsed()
    {
        var fetchCount = 0;
        var timeProvider = new FakeTimeProvider();
        var cache = new RefreshingCache<string>(timeProvider);

        Task<string> Fetch(CancellationToken _)
        {
            Interlocked.Increment(ref fetchCount);
            return Task.FromResult("value");
        }

        await cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken);
        await cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken);
        Assert.Equal(1, fetchCount);

        timeProvider.Advance(Lifetime + TimeSpan.FromMinutes(1));
        await cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken);
        Assert.Equal(2, fetchCount);
    }

    /// <summary>
    /// A forced refresh that races a failing attempt still reads the provider, rather than dereferencing
    /// the entry that attempt removed on its way out.
    /// </summary>
    /// <remarks>
    /// The interleaving is narrow but reachable, and the path it lands on is token validation: a key
    /// rotation makes several requests carry an unrecognised <c>kid</c> at once, so one caller forces a
    /// refresh while another's attempt is in flight and failing.
    /// The compare-exchange is given the entry this caller observed, so when the failing attempt has
    /// already cleared it the exchange matches nothing, publishes nothing and reports the empty slot -
    /// which is neither the entry this caller made nor one to join.
    /// The clock is the seam that makes this a fact rather than a race the test hopes to win: the cache
    /// reads it between observing the entry and exchanging it, so a clock that blocks inside that one
    /// reading pins the forced caller exactly there while the failure is delivered.
    /// </remarks>
    [Fact]
    public async Task AForcedRefreshRacingAFailingAttemptStillReads()
    {
        var attempts = 0;
        var started = new TaskCompletionSource();
        var release = new TaskCompletionSource();
        var clock = new PausableClock();
        var cache = new RefreshingCache<string>(clock);

        async Task<string> Failing()
        {
            started.SetResult();
            await release.Task;
            throw new InvalidOperationException("the provider is unreachable");
        }

        Task<string> Fetch(CancellationToken _) => Interlocked.Increment(ref attempts) == 1
            ? Failing()
            : Task.FromResult("value");

        // The attempt that will fail, published and in flight.
        var failing = cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken);
        await started.Task;

        // The forced caller is parked between observing that entry and exchanging it. It runs on its own
        // thread because everything up to the exchange happens synchronously, so parking it on the test's
        // thread would park the test.
        clock.PauseOnNextReading();
        var forced = Task.Run(
            () => cache.GetAsync(Fetch, Lifetime, forceRefresh: true, TestContext.Current.CancellationToken),
            TestContext.Current.CancellationToken);
        await clock.Arrived;

        // The failure is delivered while the forced caller waits, so the entry it observed is gone by the
        // time it resumes.
        release.SetResult();
        await Assert.ThrowsAsync<InvalidOperationException>(() => failing);

        clock.Resume();
        Assert.Equal("value", await forced);
    }

    /// <summary>
    /// A failed attempt is discarded even when the only caller waiting on it had given up first.
    /// </summary>
    /// <remarks>
    /// Discarding belongs to the attempt, not to whoever happens to be awaiting it. Tied to the caller, a
    /// single abandoned request leaves the failure held for the rest of the lifetime and every later caller
    /// is handed the same stale exception without a second attempt ever being made - the one thing this
    /// class says it does not do.
    /// </remarks>
    [Fact]
    public async Task AFailedFetchIsNotHeldEvenWhenItsOnlyCallerGaveUp()
    {
        var attempts = 0;
        var started = new TaskCompletionSource();
        var release = new TaskCompletionSource();
        var cache = new RefreshingCache<string>(new FakeTimeProvider());

        Task<string>? failing = null;

        async Task<string> Failing()
        {
            started.SetResult();
            await release.Task;
            throw new InvalidOperationException("the provider is unreachable");
        }

        // The first attempt is kept, because the test has to await the very task the cache is holding to
        // know the failure has been delivered rather than merely scheduled.
        Task<string> Fetch(CancellationToken _)
        {
            if (Interlocked.Increment(ref attempts) > 1)
                return Task.FromResult("value");

            failing = Failing();
            return failing;
        }

        using var impatient = new CancellationTokenSource();
        var abandoned = cache.GetAsync(Fetch, Lifetime, impatient.Token);
        await started.Task;

        // The only caller leaves before the attempt resolves, so nothing is left to notice its failure.
        await impatient.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => abandoned);

        release.SetResult();
        await Assert.ThrowsAsync<InvalidOperationException>(() => failing!);

        Assert.Equal("value", await cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken));
        Assert.Equal(2, attempts);
    }

    /// <summary>
    /// A clock that can be made to block inside one reading of the current time.
    /// </summary>
    /// <remarks>
    /// This is what turns an interleaving into a fact. The cache reads the clock at a known point, so
    /// holding it there places a caller exactly where the test needs it, on every run rather than on the
    /// lucky ones.
    /// </remarks>
    private sealed class PausableClock : TimeProvider
    {
        private readonly TaskCompletionSource _arrived = new();
        private readonly TaskCompletionSource _resume = new();
        private int _paused;

        /// <summary>
        /// Completes once a caller has entered the paused reading.
        /// </summary>
        public Task Arrived => _arrived.Task;

        /// <summary>
        /// Makes the next reading of the clock block until <see cref="Resume"/>.
        /// </summary>
        public void PauseOnNextReading() => Volatile.Write(ref _paused, 1);

        /// <summary>
        /// Lets the paused reading finish.
        /// </summary>
        public void Resume() => _resume.TrySetResult();

        public override DateTimeOffset GetUtcNow()
        {
            // Armed for one reading only, claimed atomically, so a later reading by any caller runs
            // straight through instead of parking a second thread nobody is waiting for.
            if (Interlocked.Exchange(ref _paused, 0) == 1)
            {
                _arrived.SetResult();
                _resume.Task.GetAwaiter().GetResult();
            }

            return DateTimeOffset.UnixEpoch;
        }
    }
}
