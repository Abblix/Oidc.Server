// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ReplayPrevention;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Jwt.UnitTests.ReplayPrevention;

/// <summary>
/// Pins the replay cache's contract over the store the host supplies: first reservation wins, a
/// repeat is recognised, callers keyed under different prefixes cannot see each other's entries,
/// and the entry lives exactly until the moment the caller named. Honoring that lifetime is the
/// store's own contract and is not re-tested here.
/// </summary>
public class DistributedReplayCacheTests
{
    private const string Prefix = "Abblix.Test:ReplayPrevention:";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    private static IDistributedCache CreateStore()
        => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    private static DistributedReplayCache CreateCache(
        IDistributedCache? store = null,
        string prefix = Prefix)
        => new(store ?? CreateStore(), new FakeTimeProvider(Now), prefix);

    [Fact]
    public async Task FirstReservation_Succeeds_RepeatIsRecognised()
    {
        var cache = CreateCache();

        Assert.True(await cache.TryReserveAsync(
            "jti-1", Now.AddMinutes(10), TestContext.Current.CancellationToken));
        Assert.False(await cache.TryReserveAsync(
            "jti-1", Now.AddMinutes(10), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task DistinctIdentifiers_DoNotShadowEachOther()
    {
        var cache = CreateCache();

        Assert.True(await cache.TryReserveAsync(
            "jti-1", Now.AddMinutes(10), TestContext.Current.CancellationToken));
        Assert.True(await cache.TryReserveAsync(
            "jti-2", Now.AddMinutes(10), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SameIdentifier_UnderAnotherPrefix_IsNotAReplay()
    {
        // The prefix is what lets unrelated profiles share one store: a DPoP proof and a Security
        // Event Token may carry the same identifier and neither is replaying the other.
        var store = CreateStore();
        var one = CreateCache(store, "Abblix.One:");
        var another = CreateCache(store, "Abblix.Two:");

        Assert.True(await one.TryReserveAsync(
            "jti-1", Now.AddMinutes(10), TestContext.Current.CancellationToken));
        Assert.True(await another.TryReserveAsync(
            "jti-1", Now.AddMinutes(10), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EntryLifetime_RunsUntilTheMomentTheCallerNamed()
    {
        // What this cache owns is turning an absolute moment into the store's relative lifetime.
        // Honoring it is the store's own job, so the recording store only observes what the
        // cache asked for.
        var store = new RecordingStore(CreateStore());
        var cache = CreateCache(store);

        Assert.True(await cache.TryReserveAsync(
            "jti-1", Now.AddMinutes(8), TestContext.Current.CancellationToken));

        Assert.Equal(TimeSpan.FromMinutes(8), Assert.Single(store.RecordedLifetimes));
    }

    [Fact]
    public async Task ExpiryAlreadyPast_StillRecordsTheSighting()
    {
        // A window that elapsed between validation and this call must not silently reserve
        // nothing: the shared primitive floors the lifetime, so the identifier is still taken.
        var store = new RecordingStore(CreateStore());
        var cache = CreateCache(store);

        Assert.True(await cache.TryReserveAsync(
            "jti-1", Now.AddMinutes(-1), TestContext.Current.CancellationToken));

        var lifetime = Assert.Single(store.RecordedLifetimes);
        Assert.True(lifetime > TimeSpan.Zero, $"A floored lifetime was expected, got {lifetime}.");
    }

    [Fact]
    public async Task EmptyIdentifier_IsRejected()
    {
        var cache = CreateCache();

        await Assert.ThrowsAsync<ArgumentException>(async () => await cache.TryReserveAsync(
            string.Empty, Now.AddMinutes(10), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A pass-through store that records the lifetime each write asked for, so the test can
    /// assert the cache's computation without re-implementing the store's expiry.
    /// </summary>
    private sealed class RecordingStore(IDistributedCache inner) : IDistributedCache
    {
        public List<TimeSpan?> RecordedLifetimes { get; } = [];

        public byte[]? Get(string key) => inner.Get(key);

        public Task<byte[]?> GetAsync(string key, CancellationToken token = default)
            => inner.GetAsync(key, token);

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        {
            RecordedLifetimes.Add(options.AbsoluteExpirationRelativeToNow);
            inner.Set(key, value, options);
        }

        public Task SetAsync(
            string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            RecordedLifetimes.Add(options.AbsoluteExpirationRelativeToNow);
            return inner.SetAsync(key, value, options, token);
        }

        public void Refresh(string key) => inner.Refresh(key);

        public Task RefreshAsync(string key, CancellationToken token = default)
            => inner.RefreshAsync(key, token);

        public void Remove(string key) => inner.Remove(key);

        public Task RemoveAsync(string key, CancellationToken token = default)
            => inner.RemoveAsync(key, token);
    }
}
