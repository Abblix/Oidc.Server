// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Globalization;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.Storages;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// What limits guessing of a user code: a growing pause after repeated failures against one code, and a
/// cap on how many failures one source may accumulate across codes.
/// </summary>
/// <remarks>
/// The two protect against different attacks, which is why a successful verification clears the first and
/// not the second: RFC 8628 section 5.1 asks the server to rate-limit user code attempts because a code a
/// person types is short, and an attacker who occasionally lands a valid code must not be able to reset
/// the cross-code budget at will.
/// <para>
/// Driven over a real store rather than against a stand-in that records calls, because what matters is
/// the answer the next attempt gets, not which method was reached. Every row here drives its failures one
/// after another; what happens when two arrive together is driven in <c>LostUpdateTests</c>, where that
/// ordering can be produced deterministically rather than hoped for.
/// </para>
/// </remarks>
public class UserCodeRateLimiterTests
{
    private const string UserCode = "WDJB-MJHT";
    private const string OtherUserCode = "BDWD-HJKL";
    private const string ClientIdentifier = "203.0.113.7";

    private readonly DateTimeOffset _now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private readonly FakeTimeProvider _time;
    private readonly IEntityStorage _storage;
    private readonly RecordingLoggerFactory _logs = new();
    private readonly UserCodeRateLimiter _rateLimiter;

    public UserCodeRateLimiterTests()
    {
        _time = new FakeTimeProvider(_now);
        _storage = new DistributedCacheStorage(
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new JsonBinarySerializer());

        _rateLimiter = new UserCodeRateLimiter(
            _logs.CreateLogger<UserCodeRateLimiter>(),
            _storage,
            new EntityStorageKeyFactory(),
            _time,
            Options.Create(new OidcOptions { DeviceAuthorization = DeviceOptions() }));
    }

    private static DeviceAuthorizationOptions DeviceOptions() => new()
    {
        CodeLifetime = TimeSpan.FromMinutes(5),
        PollingInterval = TimeSpan.FromSeconds(5),
        DeviceCodeLength = 32,
        UserCodeLength = 8,
        VerificationUri = new Uri("https://auth.example.com/device"),
        MaxFailuresBeforeBackoff = 3,
        MaxAddressFailuresPerWindow = 10,
        RateLimitWindow = TimeSpan.FromMinutes(1),
        MaxBackoffDuration = TimeSpan.FromHours(1),
        RateLimitRetention = TimeSpan.FromMinutes(2),
    };

    /// <summary>
    /// Below the threshold nothing is refused.
    /// </summary>
    [Fact]
    public async Task TwoFailures_StillLetTheNextAttemptThrough()
    {
        await Fail(2);

        Assert.True((await _rateLimiter.CheckAsync(UserCode, ClientIdentifier)).TryGetSuccess(out _));
    }

    /// <summary>
    /// The pause after the third failure is one second, and it doubles with each failure after it.
    /// </summary>
    /// <remarks>
    /// Read as the answer the next attempt gets rather than as a stored number: what a client is told is
    /// how long to wait, and that is what a caller can act on.
    /// <para>
    /// It stops at the failure before the last one the code allows, because the answer after that is not a
    /// pause at all - the code is spent, and the row above owns that. With the shipped numbers that leaves
    /// two doublings to see here; the far end of the ladder is driven below, against a cap raised to it.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(3, 1)]
    [InlineData(4, 2)]
    public async Task TheBackoffDoublesWithEachFailure(int failures, int expectedSeconds)
    {
        await Fail(failures);

        var result = await _rateLimiter.CheckAsync(UserCode, ClientIdentifier);

        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), retryAfter.RetryAfter);
    }

    /// <summary>
    /// A code whose attempts are spent is not verifiable again: what the next attempt is told to wait
    /// covers the rest of the code's life.
    /// </summary>
    /// <remarks>
    /// The growing pause only slows guessing down, and a code a person types is short enough that slowing
    /// is not enough on its own: eight digits is one of a hundred million, which a patient attacker reaches
    /// while the pause is still measured in seconds. The cap is what stops it - and it is the other half of
    /// the same sum RFC 8628 section 5.1 works, where the number of attempts allowed over a code's whole
    /// life is what decides the chance of landing one.
    /// <para>
    /// One failure short of the cap the answer is still the ordinary pause, in seconds. At the cap it is
    /// the code's remaining life, which is how a client learns there is nothing left to wait for.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(4, false)]
    [InlineData(5, true)]
    public async Task ACodeWhoseAttemptsAreSpent_IsRefusedForTheRestOfItsLife(int failures, bool spent)
    {
        await Fail(failures);

        var result = await _rateLimiter.CheckAsync(UserCode, ClientIdentifier);

        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(spent, retryAfter.RetryAfter >= TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// The remaining life of a spent code is counted from its FIRST attempt, not its last.
    /// </summary>
    /// <remarks>
    /// A code lives a fixed time from issuance, and the first attempt against it happened inside that life -
    /// so the first attempt plus one lifetime is never earlier than the code's own end, and never later than
    /// one lifetime past it. The last attempt carries no such relation: attempts can arrive until the moment
    /// the code dies, so counting from the last one promises a wait outlasting the code by however long the
    /// guessing went on.
    /// <para>
    /// Every other row here spends the allowance in one instant, where the first attempt and the last carry
    /// the same instant and the distinction is invisible. Here they are two minutes apart, so the answer says
    /// which one the code reads.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheRemainingLifeOfASpentCode_IsCountedFromItsFirstAttempt()
    {
        await Fail(1);
        _time.Advance(TimeSpan.FromMinutes(2));
        await Fail(4);

        var result = await _rateLimiter.CheckAsync(UserCode, ClientIdentifier);

        // Five minutes of life from the first attempt, two of them already gone.
        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(TimeSpan.FromMinutes(3), retryAfter.RetryAfter);
    }

    /// <summary>
    /// What a caller is told to wait is what is LEFT of the pause, not how long the pause was.
    /// </summary>
    /// <remarks>
    /// <see cref="TheBackoffDoublesWithEachFailure"/> asks at the instant the failure is recorded, where what
    /// is left of the pause and the pause itself are the same number, and an answer giving the whole length
    /// reads as correct. Asked part of the way in, the two differ, and a client acting on the larger number
    /// waits longer than it was refused for.
    /// <para>
    /// Half a second in rather than a second, so that what is left (one and a half) is also unlike what has
    /// elapsed (a half). At a second those two are equal, and the row would pass just as well for an answer
    /// measuring the wrong end of the interval.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheWait_IsWhatIsLeftOfThePause()
    {
        // The fourth failure earns two seconds.
        await Fail(4);
        _time.Advance(TimeSpan.FromMilliseconds(500));

        var result = await _rateLimiter.CheckAsync(UserCode, ClientIdentifier);

        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(TimeSpan.FromMilliseconds(1500), retryAfter.RetryAfter);
    }

    /// <summary>
    /// The pause is measured from the attempt that EARNED it, not from the first attempt against the code.
    /// </summary>
    /// <remarks>
    /// The mirror of the row above the last one, and the half that is easy to leave unpinned: the refusal for
    /// a spent code reads the first attempt, the growing pause reads the latest, and both readings are taken
    /// four lines apart from one pair of values. Every other row that reaches the pause drives its failures at
    /// one instant, where the two are the same number.
    /// <para>
    /// Measuring the pause from the first attempt does not merely shift it: the end of the pause then stops
    /// moving while the clock does not, so after it passes once no further failure can block anything. The
    /// count against a code would go on rising and refuse nothing, which is the state a guesser is working
    /// toward.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ThePause_IsMeasuredFromTheAttemptThatEarnedIt()
    {
        await Fail(3);
        _time.Advance(TimeSpan.FromSeconds(10));
        await Fail(1);

        var result = await _rateLimiter.CheckAsync(UserCode, ClientIdentifier);

        // Two seconds from the fourth failure, which has only just happened.
        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(2), retryAfter.RetryAfter);
    }

    /// <summary>
    /// The pause is measured from the failure that earned it, so waiting it out lets the next attempt in.
    /// </summary>
    [Fact]
    public async Task WaitingOutTheBackoff_LetsTheNextAttemptThrough()
    {
        await Fail(3);
        _time.Advance(TimeSpan.FromSeconds(1));

        Assert.True((await _rateLimiter.CheckAsync(UserCode, ClientIdentifier)).TryGetSuccess(out _));
    }

    /// <summary>
    /// Failures against one code do not slow attempts against another.
    /// </summary>
    [Fact]
    public async Task TheBackoffBelongsToOneCode()
    {
        await Fail(5);

        Assert.True((await _rateLimiter.CheckAsync(OtherUserCode, ClientIdentifier)).TryGetSuccess(out _));
    }

    /// <summary>
    /// A verified code forgets its own failures.
    /// </summary>
    [Fact]
    public async Task AVerifiedCode_ForgetsItsFailures()
    {
        await Fail(5);
        await _rateLimiter.RecordSuccessAsync(UserCode, ClientIdentifier);

        Assert.True((await _rateLimiter.CheckAsync(UserCode, ClientIdentifier)).TryGetSuccess(out _));
    }

    /// <summary>
    /// A verified code does not forget what its source has spent across codes.
    /// </summary>
    /// <remarks>
    /// The failures are spread over ten distinct codes, so nothing the per-code half does can account for
    /// the refusal: only the per-address count has seen all ten.
    /// </remarks>
    [Fact]
    public async Task AVerifiedCode_DoesNotForgetTheAddressBudget()
    {
        for (var i = 0; i < 10; i++)
            await _rateLimiter.RecordFailureAsync($"CODE-{i:0000}", ClientIdentifier);

        await _rateLimiter.RecordSuccessAsync(UserCode, ClientIdentifier);

        var result = await _rateLimiter.CheckAsync(UserCode, ClientIdentifier);

        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.True(retryAfter.RetryAfter > TimeSpan.Zero);
    }

    /// <summary>
    /// The cap is reached at the configured number of failures from one source, and not before.
    /// </summary>
    [Theory]
    [InlineData(9, false)]
    [InlineData(10, true)]
    public async Task TheAddressCapIsReachedAtTheConfiguredCount(int failures, bool refused)
    {
        for (var i = 0; i < failures; i++)
            await _rateLimiter.RecordFailureAsync($"CODE-{i:0000}", ClientIdentifier);

        var result = await _rateLimiter.CheckAsync(OtherUserCode, ClientIdentifier);

        Assert.Equal(refused, result.TryGetFailure(out _));
    }

    /// <summary>
    /// The count is per window: once the window the failures were spent in has passed, attempts are let
    /// through again.
    /// </summary>
    [Fact]
    public async Task ANewWindow_LetsAttemptsThroughAgain()
    {
        for (var i = 0; i < 10; i++)
            await _rateLimiter.RecordFailureAsync($"CODE-{i:0000}", ClientIdentifier);

        _time.Advance(TimeSpan.FromMinutes(1));

        Assert.True((await _rateLimiter.CheckAsync(OtherUserCode, ClientIdentifier)).TryGetSuccess(out _));
    }

    /// <summary>
    /// Failures against one source do not cap another.
    /// </summary>
    [Fact]
    public async Task TheAddressCapBelongsToOneAddress()
    {
        for (var i = 0; i < 10; i++)
            await _rateLimiter.RecordFailureAsync($"CODE-{i:0000}", ClientIdentifier);

        Assert.True((await _rateLimiter.CheckAsync(OtherUserCode, "198.51.100.23")).TryGetSuccess(out _));
    }

    /// <summary>
    /// The growing pause never exceeds the configured maximum.
    /// </summary>
    /// <remarks>
    /// Doubling reaches hours within a dozen failures, so without a ceiling a code would be answered with a
    /// wait outlasting anything a person would sit through. Driven with the attempt cap raised, because with
    /// the shipped cap the code is spent before the pause has doubled far enough to meet any sane ceiling.
    /// </remarks>
    [Fact]
    public async Task ThePause_NeverExceedsTheConfiguredMaximum()
    {
        var limiter = LimiterWith(options =>
        {
            options.MaxUserCodeAttempts = 20;
            options.MaxBackoffDuration = TimeSpan.FromSeconds(10);
            options.CodeLifetime = TimeSpan.FromHours(6);
        });

        // Ten failures earn 2^7 seconds by doubling, which the ceiling cuts to ten.
        for (var i = 0; i < 10; i++)
            await limiter.RecordFailureAsync(UserCode, ClientIdentifier);

        var result = await limiter.CheckAsync(UserCode, ClientIdentifier);

        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(10), retryAfter.RetryAfter);
    }

    /// <summary>
    /// A limiter over the same store, configured away from the shipped numbers for one row.
    /// </summary>
    private UserCodeRateLimiter LimiterWith(Action<DeviceAuthorizationOptions> configure)
    {
        var deviceOptions = DeviceOptions();
        configure(deviceOptions);

        return new UserCodeRateLimiter(
            _logs.CreateLogger<UserCodeRateLimiter>(),
            _storage,
            new EntityStorageKeyFactory(),
            _time,
            Options.Create(new OidcOptions { DeviceAuthorization = deviceOptions }));
    }

    private async Task Fail(int times)
    {
        for (var i = 0; i < times; i++)
            await _rateLimiter.RecordFailureAsync(UserCode, ClientIdentifier);
    }
}
