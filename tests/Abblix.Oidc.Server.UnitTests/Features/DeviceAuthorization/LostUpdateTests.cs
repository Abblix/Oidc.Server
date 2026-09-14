// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;
using StoredDeviceRequest = Abblix.Oidc.Server.Features.DeviceAuthorization.DeviceAuthorizationRequest;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// The places the device flow reads a record, changes it in memory and writes it back, where a change
/// that lands in between is overwritten without a trace.
/// </summary>
/// <remarks>
/// Driven deterministically, through the real handler and over the real storage. Two things make that
/// worth saying. A read-modify-write loses an update on exactly one interleaving, so a test that fires
/// threads and hopes reproduces it sometimes, which is the same as passing for the wrong reason - and the
/// shared decorator produces that interleaving once, on a named key. And the poll is driven by CALLING the
/// handler rather than by imitating it: an earlier version of these rows did the read and the write
/// themselves, so they reproduced the defect in the test and went on failing after the product stopped
/// having it.
/// </remarks>
public class LostUpdateTests
{
    private const string UserCode = "WDJB-MJHT";
    private const string DeviceCode = "device_code_abc123";
    private const string ClientIdentifier = "203.0.113.7";
    private const string RequestKey = "device:request:device_code_abc123";
    private const string UserCodeKey = "device:user-code:WDJB-MJHT";

    private readonly DateTimeOffset _now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static IEntityStorage RealStorage(IDistributedCache cache)
        => new DistributedCacheStorage(cache, new JsonBinarySerializer());

    private static IDistributedCache RealCache()
        => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    /// <summary>
    /// The user's approval lands inside the polling device's read, and that same poll answers with the
    /// tokens.
    /// </summary>
    /// <remarks>
    /// It did not before: the poll wrote the whole request back to note when the client might ask again,
    /// so an approval arriving inside that window was put back to pending and the device was told to keep
    /// waiting until the code expired.
    /// <para>
    /// The assertion is the issued grant rather than the stored status, because that is what the person
    /// standing at the device sees. A stored status would be the precondition for it.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AnApprovalLandingInsideAPoll_IsNotLost()
    {
        var cache = RealCache();
        var storage = new LetsAnotherCallerIn(RealStorage(cache), RequestKey);
        var devices = DeviceStorageOver(storage);

        await devices.StoreAsync(DeviceCode, NewRequest(), TimeSpan.FromMinutes(5));

        // What a user approving on their phone does, timed to land inside the read the handler makes.
        storage.OnNextReadOf(async () =>
        {
            var approving = DeviceStorageOver(RealStorage(cache));
            var request = await approving.TryGetByDeviceCodeAsync(DeviceCode);
            request!.Status = DeviceAuthorizationStatus.Authorized;

            // The status and the grant together, which is what approval writes: a record saying approved
            // with nothing to issue from is a different state, handled by an arm of its own.
            request.AuthorizedGrant = new AuthorizedGrant(
                new AuthSession("a-user", "a-session", _now, "device"),
                new AuthorizationContext("a-client", ["openid"], null));

            await approving.UpdateAsync(DeviceCode, request, TimeSpan.FromMinutes(5));
        });

        // The real poll, through the handler the token endpoint calls.
        var result = await DeviceHandlerOver(devices, RealStorage(cache)).AuthorizeAsync(
            new TokenRequest { DeviceCode = DeviceCode },
            new ClientInfo("a-client"),
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var grant));
        Assert.Equal("a-client", grant.Context.ClientId);

        // And the code is spent, so a second poll cannot be answered with the same grant.
        Assert.Null(await DeviceStorageOver(RealStorage(cache)).TryGetByDeviceCodeAsync(DeviceCode));
    }

    /// <summary>
    /// Two wrong guesses arriving together count as two, so the pause they earn is the pause for two.
    /// </summary>
    /// <remarks>
    /// A count kept as a number in one record loses one of them: both callers read the same number and
    /// both write it raised by one, after which a burst counts as roughly one attempt. Each failure now
    /// takes a key of its own instead, and a caller that finds its key taken moves to the next one - so
    /// the ordering driven here, the second caller running its whole cycle once the first has taken its
    /// key, is the one that used to lose an attempt and now cannot.
    /// <para>
    /// RFC 8628 section 5.1 is what makes this a security defect rather than an inaccuracy: a user code is
    /// short because a person types it, and the document's worked example has "the rate-limiting interval
    /// and validity period" allow "only 5 attempts" over a code's whole life to reach the improbability a
    /// long random token has. A count that loses most of a burst spends those attempts without charging
    /// for them. The rate limiting itself the document recommends in lower case; its capitalised SHOULD is
    /// about the code having enough entropy "when combined with rate-limiting", which is why the two are
    /// only ever judged together.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TwoFailuresArrivingTogether_AreBothCounted()
    {
        var cache = RealCache();
        var firstAttemptKey = new EntityStorageKeyFactory().UserCodeRateLimitAttemptKey(UserCode, generation: 1, attempt: 1);
        var storage = new LetsAnotherCallerIn(RealStorage(cache), firstAttemptKey);

        storage.OnNextClaimOf(() => LimiterOver(RealStorage(cache))
            .RecordFailureAsync(UserCode, ClientIdentifier));

        await LimiterOver(storage).RecordFailureAsync(UserCode, ClientIdentifier);

        // With the pause starting at the second failure, being told to wait is the whole claim: one
        // failure on record would let the next attempt straight through.
        var result = await LimiterOver(RealStorage(cache)).CheckAsync(UserCode, ClientIdentifier);

        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(1), retryAfter.RetryAfter);
    }

    /// <summary>
    /// A failure arriving while a verified code's attempts are being cleared does not inflate what the
    /// next attempts are counted as.
    /// </summary>
    /// <remarks>
    /// Clearing and claiming meet on the same keys. Clearing used to remove as many rungs as it had read a
    /// moment earlier, so a failure landing in between left its rung ABOVE the cleared run. The failure
    /// itself is not the loss - the code has just been verified, so its own history says nothing any more,
    /// and the count per address kept it. What breaks is the reader: it finds the highest rung by halving
    /// the range, which answers correctly only while the rungs are one unbroken run, so the stranded rung
    /// made the next two attempts count as three - blocking a legitimate person one attempt early, with the
    /// pause measured from somebody else's attempt.
    /// <para>
    /// The ordering needs no contrivance: a verification form submitted twice has one request succeeding
    /// while the other finds the code already taken and records a failure.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AFailureArrivingWhileACodeIsCleared_DoesNotInflateLaterCounts()
    {
        var cache = RealCache();
        var firstAttemptKey = new EntityStorageKeyFactory().UserCodeRateLimitAttemptKey(UserCode, generation: 1, attempt: 1);
        var storage = new LetsAnotherCallerIn(RealStorage(cache), firstAttemptKey);

        // Two failures are already on record, so the clearing has a range to walk.
        await LimiterOver(RealStorage(cache)).RecordFailureAsync(UserCode, ClientIdentifier);
        await LimiterOver(RealStorage(cache)).RecordFailureAsync(UserCode, ClientIdentifier);

        storage.OnNextRemovalOf(() => LimiterOver(RealStorage(cache))
            .RecordFailureAsync(UserCode, ClientIdentifier));

        await LimiterOver(storage).RecordSuccessAsync(UserCode, ClientIdentifier);

        // Two failures since the code was verified, and the pause starts at the third: the next attempt
        // must be let through. A rung stranded above the cleared run makes these two count as three.
        var after = LimiterOver(RealStorage(cache), failuresBeforeBackoff: 3);
        await after.RecordFailureAsync(UserCode, ClientIdentifier);
        await after.RecordFailureAsync(UserCode, ClientIdentifier);

        Assert.True((await after.CheckAsync(UserCode, ClientIdentifier)).TryGetSuccess(out _));
    }

    /// <summary>
    /// A failure whose own reading began before a verification cleared the code does not make later
    /// attempts count high.
    /// </summary>
    /// <remarks>
    /// The failing caller decides two things from reads: which ladder to write to, and where the claimed
    /// run ends. Either read can go stale while a verification clears the code in between, and the second
    /// one is the ordering no removal can fix - the caller places its rung above a run that is no longer
    /// there, and a reader that finds the highest rung by halving the range cannot meet a gap: two later
    /// attempts then count as three, blocking a legitimate person early with a pause measured from an
    /// attempt belonging to an earlier life of the code.
    /// <para>
    /// Both arming points are driven, because a row that produces only the first ordering stays green
    /// against a clearing that removes rungs - measured, by planting exactly that.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("which ladder", 0)]
    [InlineData("where the run ends", 2)]
    public async Task AFailureThatBeganBeforeACodeWasCleared_DoesNotMakeLaterCountsHigh(
        string ordering, int armOnRung)
    {
        var cache = RealCache();
        var keys = new EntityStorageKeyFactory();

        // Rung 2 rather than rung 1: the reader halves the range, so with two rungs taken it reads 16, 8,
        // 4 and 2, and never touches the first.
        var watched = armOnRung == 0
            ? keys.UserCodeRateLimitGenerationKey(UserCode)
            : keys.UserCodeRateLimitAttemptKey(UserCode, generation: 1, attempt: armOnRung);

        Assert.NotEmpty(ordering);
        var storage = new LetsAnotherCallerIn(RealStorage(cache), watched);

        await LimiterOver(RealStorage(cache)).RecordFailureAsync(UserCode, ClientIdentifier);
        await LimiterOver(RealStorage(cache)).RecordFailureAsync(UserCode, ClientIdentifier);

        storage.OnNextReadOf(() => LimiterOver(RealStorage(cache))
            .RecordSuccessAsync(UserCode, ClientIdentifier));

        await LimiterOver(storage).RecordFailureAsync(UserCode, ClientIdentifier);

        // Two failures since the code was verified, at most, and the pause starts at the third.
        var after = LimiterOver(RealStorage(cache), failuresBeforeBackoff: 3);
        await after.RecordFailureAsync(UserCode, ClientIdentifier);
        await after.RecordFailureAsync(UserCode, ClientIdentifier);

        Assert.True((await after.CheckAsync(UserCode, ClientIdentifier)).TryGetSuccess(out _));
    }

    private DeviceAuthorizationStorage DeviceStorageOver(IEntityStorage storage)
        => new(
            NullLogger<DeviceAuthorizationStorage>.Instance,
            storage,
            DeviceKeys(),
            new FakeTimeProvider(_now));

    /// <summary>
    /// The handler the token endpoint calls, over the storage this row controls.
    /// </summary>
    private DeviceCodeGrantHandler DeviceHandlerOver(
        IDeviceAuthorizationStorage devices, IEntityStorage forSchedule)
        => new(
            NullLogger<DeviceCodeGrantHandler>.Instance,
            devices,
            new PollScheduleStore(forSchedule),
            new EntityStorageKeyFactory(),
            StubAuthorizationDetailsPolicy.Accepting,
            new FakeTimeProvider(_now),
            Options.Create(new OidcOptions { DeviceAuthorization = DeviceOptions() }));

    private UserCodeRateLimiter LimiterOver(IEntityStorage storage, int failuresBeforeBackoff = 2)
        => new(
            NullLogger<UserCodeRateLimiter>.Instance,
            storage,
            new EntityStorageKeyFactory(),
            new FakeTimeProvider(_now),
            Options.Create(new OidcOptions
            {
                DeviceAuthorization = new DeviceAuthorizationOptions
                {
                    CodeLifetime = TimeSpan.FromMinutes(5),
                    PollingInterval = TimeSpan.FromSeconds(5),
                    DeviceCodeLength = 32,
                    UserCodeLength = 8,
                    VerificationUri = new Uri("https://auth.example.com/device"),

                    // Where the pause starts decides what a row can tell apart by asking whether the
                    // next attempt is let through.
                    MaxFailuresBeforeBackoff = failuresBeforeBackoff,
                },
            }));

    private static IEntityStorageKeyFactory DeviceKeys()
    {
        var keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Loose);
        keyFactory.Setup(f => f.DeviceAuthorizationRequestKey(DeviceCode)).Returns(RequestKey);
        keyFactory.Setup(f => f.DeviceAuthorizationUserCodeKey(UserCode)).Returns(UserCodeKey);
        return keyFactory.Object;
    }

    private static DeviceAuthorizationOptions DeviceOptions() => new()
    {
        CodeLifetime = TimeSpan.FromMinutes(5),
        PollingInterval = TimeSpan.FromSeconds(5),
        DeviceCodeLength = 32,
        UserCodeLength = 8,
        VerificationUri = new Uri("https://auth.example.com/device"),
    };

    private StoredDeviceRequest NewRequest() => new("a-client", ["openid"], null, UserCode)
    {
        Status = DeviceAuthorizationStatus.Pending,
        ExpiresAt = _now.AddMinutes(5),
    };
}
