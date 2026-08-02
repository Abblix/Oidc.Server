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
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the replay cache's contract: first registration wins, a repeat is recognised, feeds are
/// isolated by issuer, and eviction forgets only what the validation window already rejects.
/// </summary>
public class InMemoryJtiReplayCacheTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    [Fact]
    public async Task FirstRegistration_Succeeds_RepeatIsRecognised()
    {
        var cache = new InMemoryJtiReplayCache(new FakeTimeProvider(Now), TimeSpan.FromMinutes(10));

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
        var cache = new InMemoryJtiReplayCache(new FakeTimeProvider(Now), TimeSpan.FromMinutes(10));

        Assert.True(await cache.TryRegisterAsync(
            "https://one.example.com", "jti-1", Now, TestContext.Current.CancellationToken));
        Assert.True(await cache.TryRegisterAsync(
            "https://two.example.com", "jti-1", Now, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EntriesBeyondTheRetention_AreForgotten()
    {
        // Forgetting is safe exactly because the freshness step rejects anything that old before
        // the cache is ever asked; the eviction sweep runs at most once a minute, so the clock
        // must pass both the retention and a sweep boundary.
        var clock = new FakeTimeProvider(Now);
        var retention = TimeSpan.FromMinutes(10);
        var cache = new InMemoryJtiReplayCache(clock, retention);

        Assert.True(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-1", Now, TestContext.Current.CancellationToken));

        clock.Advance(retention + TimeSpan.FromMinutes(2));

        // The sweep is triggered by registrations; this one both triggers it and proves the
        // evicted identifier registers as new again.
        Assert.True(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-2", Now + retention, TestContext.Current.CancellationToken));
        Assert.True(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-1", Now + retention, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task EntriesWithinTheRetention_SurviveASweep()
    {
        var clock = new FakeTimeProvider(Now);
        var cache = new InMemoryJtiReplayCache(clock, TimeSpan.FromMinutes(10));

        Assert.True(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-1", Now, TestContext.Current.CancellationToken));

        // Past a sweep boundary but inside the retention: the identifier must still be known.
        clock.Advance(TimeSpan.FromMinutes(5));

        Assert.False(await cache.TryRegisterAsync(
            "https://issuer.example.com", "jti-1", Now, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ZeroRetention_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new InMemoryJtiReplayCache(new FakeTimeProvider(Now), TimeSpan.Zero));
    }
}
