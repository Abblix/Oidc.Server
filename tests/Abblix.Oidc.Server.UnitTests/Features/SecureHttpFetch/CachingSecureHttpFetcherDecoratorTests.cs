// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Verifies that the caching decorator actually spares the network, and that its lifetime is the one it was
/// constructed with. Asserting the type of the registered decorator is not enough: an instance built with a
/// zero lifetime is the same type and caches nothing.
/// </summary>
public class CachingSecureHttpFetcherDecoratorTests
{
    private static readonly Uri KeySetUri = new("https://issuer.example.com/.well-known/jwks.json");

    private static (CachingSecureHttpFetcherDecorator Decorator, Mock<ISecureHttpFetcher> Inner) Create(
        TimeSpan cacheDuration,
        TimeSpan? refetchInterval = null,
        TimeProvider? time = null)
    {
        var inner = new Mock<ISecureHttpFetcher>(MockBehavior.Strict);
        var cache = new MemoryCache(new MemoryCacheOptions { Clock = new StoreClock(time ?? new FakeTimeProvider()) });
        var options = new Mock<IOptionsMonitor<SecureHttpFetchOptions>>();
        options
            .Setup(monitor => monitor.CurrentValue)
            .Returns(new SecureHttpFetchOptions { RefetchInterval = refetchInterval ?? TimeSpan.FromMinutes(1) });
        return (new CachingSecureHttpFetcherDecorator(inner.Object, cache, cacheDuration, options.Object), inner);
    }

    /// <summary>
    /// A second fetch of the same document is served from the cache: the inner fetcher is called once. This is
    /// the property the registration exists for, and the one a type assertion cannot see.
    /// </summary>
    [Fact]
    public async Task SecondFetchOfTheSameUri_DoesNotReachTheInnerFetcher()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)("key-set"));

        await decorator.FetchAsync<string>(KeySetUri);
        await decorator.FetchAsync<string>(KeySetUri);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Once);
    }

    /// <summary>
    /// The lifetime comes from the instance, so a decorator built with a zero duration holds nothing and every
    /// fetch reaches the network. This is what separates one consumer's cached fetcher from another's, and it
    /// is why the duration is a constructor argument rather than a parameter of the transport contract.
    /// </summary>
    [Fact]
    public async Task ZeroCacheDuration_ReachesTheInnerFetcherEveryTime()
    {
        var (decorator, inner) = Create(TimeSpan.Zero);
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)("key-set"));

        await decorator.FetchAsync<string>(KeySetUri);
        await decorator.FetchAsync<string>(KeySetUri);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }

    /// <summary>
    /// A failed fetch is not cached, so a transient failure does not lock the consumer out for the whole
    /// lifetime: the next call tries again.
    /// </summary>
    [Fact]
    public async Task FailedFetch_IsNotCached()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync(new OidcError(ErrorCodes.ServerError, "unreachable"));

        await decorator.FetchAsync<string>(KeySetUri);
        await decorator.FetchAsync<string>(KeySetUri);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }

    /// <summary>
    /// A refetch reaches the network past the copy held and replaces it, so the fetches after it serve the
    /// document as it is now, a signer's rotated key set among them.
    /// </summary>
    [Fact]
    public async Task Refetch_ReplacesTheCopyHeld()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        inner
            .SetupSequence(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)"old-set")
            .ReturnsAsync((Result<string, OidcError>)"new-set");

        await decorator.FetchAsync<string>(KeySetUri);
        var refetched = await decorator.FetchAsync<string>(KeySetUri, refetch: true);
        var after = await decorator.FetchAsync<string>(KeySetUri);

        Assert.Equal("new-set", refetched.GetSuccess());
        Assert.Equal("new-set", after.GetSuccess());
        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }

    /// <summary>
    /// Anyone able to send a token can ask for a refetch with a kid of their choosing, so within the interval the
    /// document fetched last is served and the URI is reached once, whoever asks and however often.
    /// </summary>
    [Fact]
    public async Task RefetchesWithinTheInterval_ReachTheUriOnce()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1), refetchInterval: TimeSpan.FromHours(1));
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)"key-set");

        for (var attempt = 0; attempt < 5; attempt++)
            await decorator.FetchAsync<string>(KeySetUri, refetch: true);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Once);
    }

    /// <summary>
    /// Requests arriving together after a rotation share one refetch, so each of them sees the new set rather than
    /// the one that held when it asked.
    /// </summary>
    [Fact]
    public async Task ConcurrentRefetches_AwaitTheSameFetch()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        var pending = new TaskCompletionSource<Result<string, OidcError>>();
        inner.Setup(f => f.FetchAsync<string>(KeySetUri)).Returns(pending.Task);

        var refetches = Enumerable.Range(0, 32)
            .Select(_ => Task.Run(() => decorator.FetchAsync<string>(KeySetUri, refetch: true)))
            .ToArray();
        pending.SetResult("new-set");

        foreach (var refetch in await Task.WhenAll(refetches))
            Assert.Equal("new-set", refetch.GetSuccess());
        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Once);
    }

    /// <summary>
    /// The limit lasts its interval and no longer: once it has passed, the next refetch reaches the URI again, so a
    /// signer rotating its key a second time is accepted without waiting for the copy to expire.
    /// </summary>
    [Fact]
    public async Task ARefetchAfterTheInterval_ReachesTheUriAgain()
    {
        var time = new FakeTimeProvider();
        var (decorator, inner) = Create(TimeSpan.FromHours(1), refetchInterval: TimeSpan.FromMinutes(1), time: time);
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)"key-set");

        await decorator.FetchAsync<string>(KeySetUri, refetch: true);
        time.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));
        await decorator.FetchAsync<string>(KeySetUri, refetch: true);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }

    /// <summary>
    /// A refetch answers the next ones no longer than the copy itself is held, so it never serves a set older than
    /// the copy, in which a key its signer removed would verify again.
    /// </summary>
    [Fact]
    public async Task ARefetch_IsHeldNoLongerThanTheCopy()
    {
        var time = new FakeTimeProvider();
        var (decorator, inner) = Create(TimeSpan.FromSeconds(10), refetchInterval: TimeSpan.FromMinutes(1), time: time);
        inner
            .SetupSequence(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)"old-set")
            .ReturnsAsync((Result<string, OidcError>)"new-set");

        await decorator.FetchAsync<string>(KeySetUri, refetch: true);
        time.Advance(TimeSpan.FromSeconds(11));
        var refetched = await decorator.FetchAsync<string>(KeySetUri, refetch: true);

        Assert.Equal("new-set", refetched.GetSuccess());
    }

    /// <summary>
    /// With caching off every fetch is already fresh, so nothing is held and each refetch reaches the URI.
    /// </summary>
    [Fact]
    public async Task ZeroCacheDuration_HoldsNoRefetch()
    {
        var (decorator, inner) = Create(TimeSpan.Zero);
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)"key-set");

        await decorator.FetchAsync<string>(KeySetUri, refetch: true);
        await decorator.FetchAsync<string>(KeySetUri, refetch: true);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }

    /// <summary>
    /// A refetch that fails with no copy held has nothing to serve in its place, so the failure is returned.
    /// </summary>
    [Fact]
    public async Task FailedRefetchWithNoCopy_ReturnsTheFailure()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync(new OidcError(ErrorCodes.ServerError, "unreachable"));

        var refetched = await decorator.FetchAsync<string>(KeySetUri, refetch: true);

        Assert.True(refetched.TryGetFailure(out _));
    }

    /// <summary>
    /// A refetch that fails serves the copy that worked and leaves it held, so a caller cannot cost a signer its keys
    /// by asking for a refetch while the signer's URI is briefly unreachable.
    /// </summary>
    [Fact]
    public async Task FailedRefetch_KeepsTheCopyThatWorked()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1));
        inner
            .SetupSequence(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)"key-set")
            .ReturnsAsync(new OidcError(ErrorCodes.ServerError, "unreachable"));

        await decorator.FetchAsync<string>(KeySetUri);
        var refetched = await decorator.FetchAsync<string>(KeySetUri, refetch: true);
        var after = await decorator.FetchAsync<string>(KeySetUri);

        Assert.Equal("key-set", refetched.GetSuccess());
        Assert.Equal("key-set", after.GetSuccess());
        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }

    /// <summary>
    /// A host setting the interval to zero turns the limit off, so every refetch reaches the URI.
    /// </summary>
    [Fact]
    public async Task ZeroRefetchInterval_ReachesTheUriOnEveryRefetch()
    {
        var (decorator, inner) = Create(TimeSpan.FromHours(1), refetchInterval: TimeSpan.Zero);
        inner
            .Setup(f => f.FetchAsync<string>(KeySetUri))
            .ReturnsAsync((Result<string, OidcError>)"key-set");

        await decorator.FetchAsync<string>(KeySetUri, refetch: true);
        await decorator.FetchAsync<string>(KeySetUri, refetch: true);

        inner.Verify(f => f.FetchAsync<string>(KeySetUri), Times.Exactly(2));
    }
}
