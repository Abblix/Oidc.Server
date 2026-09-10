// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Redis;
using Abblix.Tests.Shared;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// Holds the store to the contract <see cref="IEntityStorage"/> states, against a REAL Redis-protocol
/// server: the embedded Garnet the shared fixture starts.
/// </summary>
/// <remarks>
/// A fake would answer whatever this test taught it, and the claim that matters is what the SERVER does
/// when two callers arrive together. Only a server that actually serializes commands can settle it.
/// </remarks>
public sealed class RedisEntityStorageTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly StorageOptions OneMinute =
        new() { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1) };

    private RedisEntityStorage NewStorage() => new(
        garnet.Connection,
        new JsonBinarySerializer(),
        TimeProvider.System,
        new RedisEntityStorageOptions { KeyPrefix = $"test:{Guid.NewGuid():N}:" });

    private static string NewKey() => $"entity:{Guid.NewGuid():N}";

    private sealed record Stored(string Value, int Number);

    [Fact]
    public async Task SetThenGet_WithoutRemoving_ReturnsTheEntityAndLeavesIt()
    {
        var storage = NewStorage();
        var key = NewKey();

        await storage.SetAsync(key, new Stored("an-authorization", 1), OneMinute, Ct);

        Assert.Equal(new Stored("an-authorization", 1), await storage.GetAsync<Stored>(key, false, Ct));
        Assert.Equal(new Stored("an-authorization", 1), await storage.GetAsync<Stored>(key, false, Ct));
    }

    [Fact]
    public async Task GetAsync_AKeyHoldingNothing_ReturnsNull()
    {
        Assert.Null(await NewStorage().GetAsync<Stored>(NewKey(), false, Ct));
    }

    [Fact]
    public async Task SetAsync_OverAnExistingEntry_ReplacesIt()
    {
        var storage = NewStorage();
        var key = NewKey();

        await storage.SetAsync(key, new Stored("first", 1), OneMinute, Ct);
        await storage.SetAsync(key, new Stored("second", 2), OneMinute, Ct);

        Assert.Equal(new Stored("second", 2), await storage.GetAsync<Stored>(key, false, Ct));
    }

    [Fact]
    public async Task RemoveAsync_AStoredEntry_LeavesNothingToRead()
    {
        var storage = NewStorage();
        var key = NewKey();

        await storage.SetAsync(key, new Stored("an-authorization", 1), OneMinute, Ct);
        await storage.RemoveAsync(key, Ct);

        Assert.Null(await storage.GetAsync<Stored>(key, false, Ct));
    }

    [Fact]
    public async Task GetAsync_RemovingOnRetrieval_AnswersTheSecondCallerNothing()
    {
        var storage = NewStorage();
        var key = NewKey();

        await storage.SetAsync(key, new Stored("an-authorization", 1), OneMinute, Ct);

        Assert.Equal(new Stored("an-authorization", 1), await storage.GetAsync<Stored>(key, true, Ct));
        Assert.Null(await storage.GetAsync<Stored>(key, true, Ct));
    }

    /// <summary>
    /// A policy naming no deadline stores an entry that does not expire, and one naming a span sets it.
    /// </summary>
    /// <remarks>
    /// Not a hypothetical boundary: <c>RegistrationAccessTokenStore</c> writes without a deadline on
    /// purpose, because a registration access token stays valid while the client is registered and
    /// RFC 7592 section 5 forbids expiring it. A store refusing that write would break dynamic client
    /// registration for every host that registered it.
    /// <para>
    /// The deadline is read back off the SERVER. Asserting on the policy handed in would restate what
    /// the test itself passed, which is true by construction and measures nothing; and the pair is
    /// asserted together so that a storage setting no expiry ever cannot pass the first half alone.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task SetAsync_ADeadlineOrNone_IsWhatTheServerHoldsAfterwards()
    {
        const string prefix = "test-ttl:";
        var storage = new RedisEntityStorage(
            garnet.Connection,
            new JsonBinarySerializer(),
            TimeProvider.System,
            new RedisEntityStorageOptions { KeyPrefix = prefix });

        var forever = NewKey();
        await storage.SetAsync(forever, new Stored("a-registration-token", 1), new StorageOptions(), Ct);

        Assert.Equal(
            new Stored("a-registration-token", 1),
            await storage.GetAsync<Stored>(forever, false, Ct));
        Assert.Null(await garnet.Connection.GetDatabase().KeyTimeToLiveAsync(prefix + forever));

        var expiring = NewKey();
        await storage.SetAsync(expiring, new Stored("an-authorization", 2), OneMinute, Ct);

        var left = await garnet.Connection.GetDatabase().KeyTimeToLiveAsync(prefix + expiring);
        Assert.NotNull(left);
        Assert.InRange(left.Value, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(1));
    }


    /// <summary>
    /// A deadline already behind us leaves nothing readable, and takes any earlier entry with it.
    /// </summary>
    /// <remarks>
    /// Reachable from the product: a token's status is written to expire when the token does, so an
    /// already-expired token asks for a deadline in the past. Redis refuses a non-positive lifetime, and
    /// silently doing nothing would be worse than refusing - the key would keep whatever it held, while
    /// this method's whole contract is that it replaces it.
    /// </remarks>
    [Fact]
    public async Task SetAsync_ADeadlineAlreadyBehindUs_LeavesNothingReadable()
    {
        var storage = NewStorage();
        var key = NewKey();
        var past = new StorageOptions { AbsoluteExpiration = DateTimeOffset.UnixEpoch };

        await storage.SetAsync(key, new Stored("an-authorization", 1), OneMinute, Ct);
        await storage.SetAsync(key, new Stored("too-late", 2), past, Ct);

        Assert.Null(await storage.GetAsync<Stored>(key, false, Ct));
    }

    /// <summary>
    /// A sliding deadline is refused, because honoring it would let a polling client keep a code alive.
    /// </summary>
    [Fact]
    public async Task SetAsync_ASlidingDeadline_IsRefused()
    {
        var options = new StorageOptions { SlidingExpiration = TimeSpan.FromMinutes(1) };

        await Assert.ThrowsAsync<ArgumentException>(
            () => NewStorage().SetAsync(NewKey(), new Stored("x", 1), options, Ct));
    }

    /// <summary>
    /// The claim this package exists for: many callers, one winner, and the value never destroyed with
    /// nobody told it won.
    /// </summary>
    /// <remarks>
    /// Driven against the server rather than reasoned about, and repeated over many keys, because a race
    /// that resolves correctly once may only have failed to interleave.
    /// </remarks>
    [Fact]
    public async Task GetAsync_ManyCallersRemovingAtOnce_HandsTheEntityToExactlyOne()
    {
        const int keys = 50;
        const int callersPerKey = 8;

        var storage = NewStorage();

        for (var i = 0; i < keys; i++)
        {
            var key = NewKey();
            await storage.SetAsync(key, new Stored("an-authorization", i), OneMinute, Ct);

            var takes = Enumerable
                .Range(0, callersPerKey)
                .Select(_ => Task.Run(() => storage.GetAsync<Stored>(key, true, Ct), Ct))
                .ToArray();

            var results = await Task.WhenAll(takes);

            Assert.Equal(1, results.Count(entity => entity is not null));
        }
    }
}
