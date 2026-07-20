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

using Abblix.Oidc.Client.Internals;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Internals;

/// <summary>
/// Tests for <see cref="RefreshingCache{T}"/>, the primitive that keeps the client from asking the provider
/// the same question twice at once.
/// </summary>
public class RefreshingCacheTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

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

        async Task<string> Fetch(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref fetchCount);
            await release.Task;
            return "value";
        }

        // Started while the fetch is deliberately held open, so every caller is in flight at once.
        var callers = Enumerable
            .Range(0, 20)
            .Select(_ => cache.GetAsync(Fetch, Lifetime, TestContext.Current.CancellationToken))
            .ToArray();

        release.SetResult();
        var results = await Task.WhenAll(callers);

        Assert.Equal(1, fetchCount);
        Assert.All(results, result => Assert.Equal("value", result));
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

        async Task<string> Fetch(CancellationToken cancellationToken)
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

        Task<string> Fetch(CancellationToken cancellationToken) => ++attempt == 1
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

        async Task<string> Fetch(CancellationToken cancellationToken)
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

        Task<string> Fetch(CancellationToken cancellationToken)
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
}
