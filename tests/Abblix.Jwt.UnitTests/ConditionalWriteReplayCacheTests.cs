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

using Abblix.Jwt.ReplayPrevention;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The three things this class owns, and only those: the lifetime it asks for, the key it composes,
/// and the verdict it passes back. Whether the backend's write is indivisible is the backend's
/// promise - asserting it here would be testing somebody else's client library.
/// </summary>
public class ConditionalWriteReplayCacheTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>Records what the cache asked for, and answers what the test tells it to.</summary>
    private sealed class RecordingBackend(bool answer)
    {
        public string? Key { get; private set; }

        public TimeSpan TimeToLive { get; private set; }

        public int Calls { get; private set; }

        public CancellationToken Token { get; private set; }

        public Task<bool> ReserveIfAbsentAsync(string key, TimeSpan timeToLive, CancellationToken cancellationToken)
        {
            Key = key;
            TimeToLive = timeToLive;
            Token = cancellationToken;
            Calls++;
            return Task.FromResult(answer);
        }
    }

    private static ConditionalWriteReplayCache NewCache(RecordingBackend backend, string prefix = "replay:")
        => new(backend.ReserveIfAbsentAsync, new FakeTimeProvider(Now), prefix);

    [Fact]
    public async Task TheBackendsAnswer_IsTheVerdict_InBothDirections()
    {
        var cancellationToken = TestContext.Current.CancellationToken;

        var accepted = new RecordingBackend(answer: true);
        Assert.True(await NewCache(accepted).TryReserveAsync("jti-1", Now.AddMinutes(5), cancellationToken));

        // A backend that says the key was already there is reporting a replay, and the cache must
        // not soften that into anything else - it is the only observation of the fact there is.
        var refused = new RecordingBackend(answer: false);
        Assert.False(await NewCache(refused).TryReserveAsync("jti-1", Now.AddMinutes(5), cancellationToken));

        Assert.Equal(1, accepted.Calls);
        Assert.Equal(1, refused.Calls);
    }

    [Fact]
    public async Task TheKey_CarriesThePrefix_SoTwoNamespacesCannotSeeEachOther()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var backend = new RecordingBackend(answer: true);

        await NewCache(backend, "rollout-after:").TryReserveAsync("jti-1", Now.AddMinutes(5), cancellationToken);

        Assert.Equal("rollout-after:jti-1", backend.Key);
    }

    [Fact]
    public async Task TheLifetime_IsTheFreshnessWindow_WhileItLasts()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var backend = new RecordingBackend(answer: true);

        await NewCache(backend).TryReserveAsync("jti-1", Now.AddMinutes(5), cancellationToken);

        Assert.Equal(TimeSpan.FromMinutes(5), backend.TimeToLive);

        // The backend is the only thing here that performs I/O, so a token that stopped at this
        // class would leave the one cancellable operation uncancellable.
        Assert.Equal(cancellationToken, backend.Token);
    }

    /// <summary>
    /// The floor, tested through the case it exists for. A caller whose clock is behind asks to
    /// remember a token for a negative time; backends reject a non-positive expiry, typically
    /// before the request leaves the process, so the unfloored call would throw rather than record.
    /// A caller reading that failure as "not seen before" accepts every replay.
    /// </summary>
    [Fact]
    public async Task AnExpiryAlreadyElapsed_StillAsksForAPositiveLifetime()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var backend = new RecordingBackend(answer: true);

        Assert.True(await NewCache(backend)
            .TryReserveAsync("jti-1", Now.AddSeconds(-30), cancellationToken));

        Assert.True(backend.TimeToLive > TimeSpan.Zero);
    }

    [Fact]
    public async Task AnEmptyIdentifier_IsRefused_RatherThanReservingThePrefixItself()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var backend = new RecordingBackend(answer: true);
        var cache = NewCache(backend);

        await Assert.ThrowsAsync<ArgumentException>(
            () => cache.TryReserveAsync("", Now.AddMinutes(5), cancellationToken));

        // Nothing reached the backend: reserving the bare prefix would make the FIRST real token
        // under it read as a replay.
        Assert.Equal(0, backend.Calls);
    }
}
