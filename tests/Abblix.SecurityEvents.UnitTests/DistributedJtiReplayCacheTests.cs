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

using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the replay cache's contract over the store the host supplies: first registration wins, a
/// repeat is recognised, feeds are isolated by issuer even against adversarial key material, and
/// the entry lives exactly until its token's issue time plus the retention. Honoring that lifetime
/// is the store's own contract and is not re-tested here.
/// </summary>
public class DistributedJtiReplayCacheTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    private static IDistributedCache CreateStore()
        => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    [Fact]
    public async Task FirstRegistration_Succeeds_RepeatIsRecognised()
    {
        var cache = new DistributedJtiReplayCache(
            CreateStore(), new FakeTimeProvider(Now), TimeSpan.FromMinutes(10));

        Assert.True(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-1", Now, TestContext.Current.CancellationToken));
        Assert.False(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-1", Now, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SameIdentifier_FromAnotherIssuer_IsNotAReplay()
    {
        // "jti" is unique "within a particular event feed" (RFC 8417 Section 2.2): two issuers
        // may mint the same identifier and neither is replaying the other.
        var cache = new DistributedJtiReplayCache(
            CreateStore(), new FakeTimeProvider(Now), TimeSpan.FromMinutes(10));

        Assert.True(await cache.TryRegisterAsync(
            "https://one.example.com", "jti-1", Now, TestContext.Current.CancellationToken));
        Assert.True(await cache.TryRegisterAsync(
            "https://two.example.com", "jti-1", Now, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AdjacentIssuerAndIdentifier_DoNotCollideOnOneKey()
    {
        // A naive "issuer + separator + jti" key would map both pairs below onto one string,
        // letting a token from one feed shadow a token from another. Escaping keeps the
        // separator unambiguous, so the pairs stay distinct entries.
        var cache = new DistributedJtiReplayCache(
            CreateStore(), new FakeTimeProvider(Now), TimeSpan.FromMinutes(10));

        Assert.True(await cache.TryRegisterAsync(
            "https://t.example.com", "a:b", Now, TestContext.Current.CancellationToken));
        Assert.True(await cache.TryRegisterAsync(
            "https://t.example.com:a", "b", Now, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EntryLifetime_IsTheTokenIssueTimePlusTheRetention()
    {
        // What this cache owns is the lifetime computation; the store owns honoring it. The
        // recording store observes what the cache asked for: a token issued two minutes ago
        // under a ten-minute retention has eight minutes left to be replayed.
        var store = new RecordingStore(CreateStore());
        var retention = TimeSpan.FromMinutes(10);
        var issuedAt = Now - TimeSpan.FromMinutes(2);
        var cache = new DistributedJtiReplayCache(store, new FakeTimeProvider(Now), retention);

        Assert.True(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-1", issuedAt, TestContext.Current.CancellationToken));

        Assert.Equal(
            issuedAt + retention - Now,
            Assert.Single(store.RecordedLifetimes));
    }

    [Fact]
    public void ZeroRetention_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new DistributedJtiReplayCache(
            CreateStore(), new FakeTimeProvider(Now), TimeSpan.Zero));
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
