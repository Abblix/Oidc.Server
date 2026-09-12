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
using RateLimitState = Abblix.Oidc.Server.Features.Storages.Proto.RateLimitState;
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
    private const string RateLimitKey = "rate-limit:user-code:WDJB-MJHT";
    private const string IpKey = "rate-limit:ip:203.0.113.7";

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
        var storage = new LetsAnotherCallerInMidRead(RealStorage(cache), RequestKey);
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
    /// Two wrong guesses arriving together count as two, so the backoff and the per-address limit see what
    /// actually happened.
    /// </summary>
    /// <remarks>
    /// The counters are read, raised in memory and written back, so a second guess whose cycle completes
    /// inside the first one's read writes the same number twice. A burst then counts as roughly one.
    /// RFC 8628 section 5.1 is what makes that a security defect rather than an inaccuracy: a user code
    /// is short because a person types it, and the document's own worked example allows "only 5 attempts"
    /// within the rate-limiting interval to reach the same improbability as a long random token. A count
    /// that loses most of a burst spends those attempts without charging for them.
    /// </remarks>
    [Fact]
    public async Task TwoFailuresArrivingTogether_AreBothCounted()
    {
        var cache = RealCache();
        var storage = new LetsAnotherCallerInMidRead(RealStorage(cache), RateLimitKey);
        var limiter = LimiterOver(storage);

        storage.OnNextReadOf(() => LimiterOver(RealStorage(cache))
            .RecordFailureAsync(UserCode, ClientIdentifier));

        await limiter.RecordFailureAsync(UserCode, ClientIdentifier);

        var state = await RealStorage(cache).GetAsync<RateLimitState>(RateLimitKey, false);
        Assert.NotNull(state);
        Assert.Equal(2, state.FailureCount);
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
    {
        var keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Loose);
        keyFactory.Setup(f => f.UserCodeRateLimitKey(UserCode)).Returns(RateLimitKey);
        keyFactory.Setup(f => f.IpRateLimitKey(ClientIdentifier)).Returns(IpKey);

        return new UserCodeRateLimiter(
            NullLogger<UserCodeRateLimiter>.Instance,
            storage,
            keyFactory.Object,
            new FakeTimeProvider(_now),
            Options.Create(new OidcOptions { DeviceAuthorization = DeviceOptions() }));
    }

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
