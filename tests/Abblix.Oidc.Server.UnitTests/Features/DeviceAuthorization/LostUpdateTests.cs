// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.Storages;
// Aliased rather than imported: the generated namespace also carries a DeviceAuthorizationRequest,
// and the one this file means is the domain record.
using RateLimitState = Abblix.Oidc.Server.Features.Storages.Proto.RateLimitState;
// Aliased for the same reason, and because this file sits inside a namespace whose own
// Features.BackChannelAuthentication would otherwise win the lookup.
using CibaRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DeviceAuthorization;

/// <summary>
/// The two places the device flow reads a record, changes it in memory and writes it back, where a
/// change that lands in between is overwritten without a trace.
/// </summary>
/// <remarks>
/// Driven deterministically rather than by racing threads. A read-modify-write loses an update only on
/// one interleaving - the second caller's whole cycle completing between the first caller's read and its
/// write - and a test that fires threads and hopes reproduces that sometimes, which is the same as
/// reporting a pass for the wrong reason. <see cref="LetsAnotherCallerInMidRead"/> produces exactly that
/// interleaving, once, on a named key.
/// <para>
/// The storage underneath is the real one over a real memory cache: the defect lives in the ORDER of
/// store calls, so a mocked storage answering from a dictionary the test controls would be measuring the
/// test's own bookkeeping.
/// </para>
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
    private const string CibaRequestId = "ciba_request_abc123";
    private const string CibaRequestKey = "ciba:request:ciba_request_abc123";

    private readonly DateTimeOffset _now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static IEntityStorage RealStorage(IDistributedCache cache)
        => new DistributedCacheStorage(cache, new JsonBinarySerializer());

    private static IDistributedCache RealCache()
        => new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    /// <summary>
    /// The user's approval lands between the polling device's read and its write, and the write puts the
    /// request back to pending - so the approval is gone and the device polls until the code expires.
    /// </summary>
    /// <remarks>
    /// The poll path re-reads the record and writes only while it still says pending, which narrows this
    /// window and does not close it: the re-read is itself a separate call, and the approval can land
    /// after it.
    /// </remarks>
    [Fact]
    public async Task AnApprovalLandingInsideAPoll_IsNotLost()
    {
        var cache = RealCache();
        var storage = new LetsAnotherCallerInMidRead(RealStorage(cache), RequestKey);
        var devices = DeviceStorageOver(storage);

        await devices.StoreAsync(DeviceCode, NewRequest(), TimeSpan.FromMinutes(5));

        // What a user approving on their phone does, timed to land inside the poll's own read.
        storage.OnNextReadOf(async () =>
        {
            var approving = DeviceStorageOver(RealStorage(cache));
            var request = await approving.TryGetByDeviceCodeAsync(DeviceCode);
            request!.Status = DeviceAuthorizationStatus.Authorized;
            await approving.UpdateAsync(DeviceCode, request, TimeSpan.FromMinutes(5));
        });

        // What the device does on its next poll: note when it may ask again.
        var polled = await devices.TryGetByDeviceCodeAsync(DeviceCode);
        polled!.NextPollAt = _now.AddSeconds(5);
        await devices.UpdateAsync(DeviceCode, polled, TimeSpan.FromMinutes(5));

        var stored = await DeviceStorageOver(RealStorage(cache)).TryGetByDeviceCodeAsync(DeviceCode);
        Assert.NotNull(stored);
        Assert.Equal(DeviceAuthorizationStatus.Authorized, stored.Status);
    }

    /// <summary>
    /// The same thing one flow over: a completed authentication landing inside a poll survives it.
    /// </summary>
    /// <remarks>
    /// The decoupled-authentication poll writes the whole request back to note when the client may ask
    /// again, so a completion that lands between its read and its write is overwritten and the client is
    /// told to keep waiting until the request expires.
    /// <para>
    /// The remark on that method calls the race benign, and for the race it describes - two polls
    /// overwriting each other's next-poll time - it is: both write about the same instant. It does not
    /// describe this one, where what is overwritten is the status.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ACompletionLandingInsideACibaPoll_IsNotLost()
    {
        var cache = RealCache();
        var storage = new LetsAnotherCallerInMidRead(RealStorage(cache), CibaRequestKey);
        var requests = CibaStorageOver(storage);

        var requestId = await requests.StoreAsync(NewCibaRequest(), TimeSpan.FromMinutes(5));

        // What the user completing authentication elsewhere does, timed to land inside the poll's read.
        storage.OnNextReadOf(async () =>
        {
            var completing = CibaStorageOver(RealStorage(cache));
            var request = await completing.TryGetAsync(requestId);
            request!.Status = BackChannelAuthenticationStatus.Authenticated;
            await completing.UpdateAsync(requestId, request, TimeSpan.FromMinutes(5));
        });

        // What the polling client's request does: note when it may ask again.
        var polled = await requests.TryGetAsync(requestId);
        polled!.NextPollAt = _now.AddSeconds(5);
        await requests.UpdateAsync(requestId, polled, TimeSpan.FromMinutes(5));

        var stored = await CibaStorageOver(RealStorage(cache)).TryGetAsync(requestId);
        Assert.NotNull(stored);
        Assert.Equal(BackChannelAuthenticationStatus.Authenticated, stored.Status);
    }

    /// <summary>
    /// Two wrong guesses arriving together count as two, so the backoff and the per-address limit see
    /// what actually happened.
    /// </summary>
    /// <remarks>
    /// The counters are read, raised in memory and written back, so a second guess whose cycle completes
    /// inside the first one's read writes the same number twice. A burst then counts as roughly one, and
    /// RFC 8628 section 5.2 names this limit as the defense a short user code has.
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

    private static BackChannelRequestStorage CibaStorageOver(IEntityStorage storage)
    {
        var keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Loose);
        keyFactory
            .Setup(f => f.BackChannelAuthenticationRequestKey(It.IsAny<string>()))
            .Returns(CibaRequestKey);

        var ids = new Mock<IAuthenticationRequestIdGenerator>(MockBehavior.Loose);
        ids.Setup(g => g.GenerateAuthenticationRequestId()).Returns(CibaRequestId);

        return new BackChannelRequestStorage(storage, ids.Object, keyFactory.Object);
    }

    private CibaRequest NewCibaRequest() => new(
        new AuthorizedGrant(
            new AuthSession("a-subject", "a-session", _now, "a-provider"),
            new AuthorizationContext("a-client", ["openid"], null)),
        _now.AddMinutes(5))
    {
        Status = BackChannelAuthenticationStatus.Pending,
        NextPollAt = _now,
    };

    private DeviceAuthorizationStorage DeviceStorageOver(IEntityStorage storage)
    {
        var keyFactory = new Mock<IEntityStorageKeyFactory>(MockBehavior.Loose);
        keyFactory.Setup(f => f.DeviceAuthorizationRequestKey(DeviceCode)).Returns(RequestKey);
        keyFactory.Setup(f => f.DeviceAuthorizationUserCodeKey(UserCode)).Returns(UserCodeKey);

        return new DeviceAuthorizationStorage(
            NullLogger<DeviceAuthorizationStorage>.Instance,
            storage,
            keyFactory.Object,
            new FakeTimeProvider(_now));
    }

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
            Options.Create(new OidcOptions
            {
                DeviceAuthorization = new DeviceAuthorizationOptions
                {
                    CodeLifetime = TimeSpan.FromMinutes(5),
                    PollingInterval = TimeSpan.FromSeconds(5),
                    DeviceCodeLength = 32,
                    UserCodeLength = 8,
                    VerificationUri = new Uri("https://auth.example.com/device"),
                },
            }));
    }

    private DeviceAuthorizationRequest NewRequest() => new("a-client", ["openid"], null, UserCode)
    {
        Status = DeviceAuthorizationStatus.Pending,
        ExpiresAt = _now.AddMinutes(5),
    };

    /// <summary>
    /// A storage that, once, runs somebody else's whole cycle in the middle of a read of one named key.
    /// </summary>
    /// <remarks>
    /// This is the interleaving a read-modify-write loses an update on, and the only one: the second
    /// caller must finish writing after the first caller has read and before it writes. Firing threads
    /// reaches it by luck, so a green run would say nothing about whether the defect is there.
    /// <para>
    /// Armed once and disarmed on use, so the second caller's own reads of the same key do not recurse.
    /// </para>
    /// </remarks>
    private sealed class LetsAnotherCallerInMidRead(IEntityStorage inner, string watched) : IEntityStorage
    {
        private Func<Task>? _other;

        public void OnNextReadOf(Func<Task> other) => _other = other;

        public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
            => inner.SetAsync(key, value, options, token);

        public async Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
        {
            var read = await inner.GetAsync<T>(key, removeOnRetrieval, token);

            if (key == watched && Interlocked.Exchange(ref _other, null) is { } other)
                await other();

            return read;
        }

        public Task RemoveAsync(string key, CancellationToken? token = null)
            => inner.RemoveAsync(key, token);
    }
}
