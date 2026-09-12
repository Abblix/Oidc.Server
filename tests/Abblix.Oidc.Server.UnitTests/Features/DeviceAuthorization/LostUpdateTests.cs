// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
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
    /// The user's approval lands between the polling device's read and its write, and survives.
    /// </summary>
    /// <remarks>
    /// It did not before: the poll wrote the whole request back to note when the client might ask again,
    /// so an approval arriving inside that window was put back to pending and the device was told to keep
    /// waiting until the code expired.
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
            await approving.UpdateAsync(DeviceCode, request, TimeSpan.FromMinutes(5));
        });

        // The real poll, through the handler the token endpoint calls.
        await DeviceHandlerOver(devices, RealStorage(cache)).AuthorizeAsync(
            new TokenRequest { DeviceCode = DeviceCode },
            new ClientInfo("a-client"),
            TestContext.Current.CancellationToken);

        var stored = await DeviceStorageOver(RealStorage(cache)).TryGetByDeviceCodeAsync(DeviceCode);
        Assert.NotNull(stored);
        Assert.Equal(DeviceAuthorizationStatus.Authorized, stored.Status);
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
    /// short because a person types it, and the document's own worked example allows "only 5 attempts"
    /// within the rate-limiting interval to reach the same improbability as a long random token. A count
    /// that loses most of a burst spends those attempts without charging for them.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TwoFailuresArrivingTogether_AreBothCounted()
    {
        var cache = RealCache();
        var firstAttemptKey = new EntityStorageKeyFactory().UserCodeRateLimitAttemptKey(UserCode, 1);
        var storage = new LetsAnotherCallerIn(RealStorage(cache), firstAttemptKey);

        storage.OnNextClaimOf(() => LimiterOver(RealStorage(cache))
            .RecordFailureAsync(UserCode, ClientIdentifier));

        await LimiterOver(storage).RecordFailureAsync(UserCode, ClientIdentifier);

        // With the pause starting at the second failure, being told to wait is the whole claim: one
        // failure on record would let the next attempt straight through.
        var result = await LimiterOver(RealStorage(cache)).CheckAsync(UserCode, ClientIdentifier);

        Assert.True(result.TryGetFailure(out var retryAfter));
        Assert.Equal(TimeSpan.FromSeconds(1), retryAfter);
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

    private UserCodeRateLimiter LimiterOver(IEntityStorage storage)
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

                    // The pause starts at the second failure, so one failure and two are told apart by
                    // what the next attempt is answered with.
                    MaxFailuresBeforeBackoff = 2,
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
