// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Redis;
using Abblix.Tests.Shared;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// The other two redemptions the package names, driven through the real storages rather than through the
/// store on its own.
/// </summary>
/// <remarks>
/// A registration that reads as configured and reaches a different store is the failure this file exists
/// to refuse, and it is invisible to every test that drives the store directly. Both of these records
/// live a whole life - written, polled without being consumed, overwritten, and finally taken once - so
/// each stage has to reach the same place as the others.
/// </remarks>
public sealed class DeviceAndCibaRedemptionTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private static readonly DateTimeOffset Instant = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private IEntityStorage NewStorage() => new RedisEntityStorage(
        garnet.Connection,
        new JsonBinarySerializer(),
        TimeProvider.System,
        new RedisEntityStorageOptions { KeyPrefix = $"test:{Guid.NewGuid():N}:" });

    private DeviceAuthorizationStorage NewDeviceStorage() => new(
        NullLogger<DeviceAuthorizationStorage>.Instance,
        NewStorage(),
        new EntityStorageKeyFactory(),
        TimeProvider.System);

    private BackChannelRequestStorage NewCibaStorage() => new(
        NewStorage(),
        new StubRequestIdGenerator(),
        new EntityStorageKeyFactory());

    private sealed class StubRequestIdGenerator : IAuthenticationRequestIdGenerator
    {
        public string GenerateAuthenticationRequestId() => Guid.NewGuid().ToString("N");
    }

    private static BackChannelAuthenticationRequest NewCibaRequest() => new(
        new AuthorizedGrant(
            new AuthSession("a-subject", "a-session", Instant, "a-provider"),
            new AuthorizationContext("a-client", ["openid"], null)),
        Instant.AddMinutes(5));

    [Fact]
    public async Task ADeviceCode_IsPolledThenClaimedOnce()
    {
        var storage = NewDeviceStorage();
        var deviceCode = Guid.NewGuid().ToString("N");
        var userCode = Guid.NewGuid().ToString("N")[..8];

        await storage.StoreAsync(
            deviceCode,
            new DeviceAuthorizationRequest("a-client", ["openid"], null, userCode),
            Lifetime);

        // Polling reads the record without consuming it, and finds it by either code.
        Assert.NotNull(await storage.TryGetByDeviceCodeAsync(deviceCode));
        Assert.NotNull(await storage.TryGetByUserCodeAsync(userCode));

        Assert.True(await storage.TryRemoveAsync(deviceCode, userCode));
        Assert.False(await storage.TryRemoveAsync(deviceCode, userCode));
        Assert.Null(await storage.TryGetByDeviceCodeAsync(deviceCode));
    }

    [Fact]
    public async Task ADeviceCodeUpdatedWhilePending_KeepsWhatWasWrittenUntilItIsClaimed()
    {
        var storage = NewDeviceStorage();
        var deviceCode = Guid.NewGuid().ToString("N");
        var userCode = Guid.NewGuid().ToString("N")[..8];
        var request = new DeviceAuthorizationRequest("a-client", ["openid"], null, userCode);

        await storage.StoreAsync(deviceCode, request, Lifetime);

        request.Status = DeviceAuthorizationStatus.Authorized;
        await storage.UpdateAsync(deviceCode, request, Lifetime);

        var polled = await storage.TryGetByDeviceCodeAsync(deviceCode);
        Assert.Equal(DeviceAuthorizationStatus.Authorized, polled!.Status);

        Assert.True(await storage.TryRemoveAsync(deviceCode, userCode));

        // The claim consumed it, which is the half a row asserting only the first claim cannot see.
        Assert.False(await storage.TryRemoveAsync(deviceCode, userCode));
    }

    [Fact]
    public async Task ManyInstancesClaimingOneDeviceCode_TellExactlyOneItTookIt()
    {
        const int codes = 25;
        const int instances = 8;

        var storage = NewDeviceStorage();

        for (var i = 0; i < codes; i++)
        {
            var deviceCode = Guid.NewGuid().ToString("N");
            var userCode = Guid.NewGuid().ToString("N")[..8];

            await storage.StoreAsync(
                deviceCode,
                new DeviceAuthorizationRequest("a-client", ["openid"], null, userCode),
                Lifetime);

            var claims = await Task.WhenAll(Enumerable
                .Range(0, instances)
                .Select(_ => Task.Run(() => storage.TryRemoveAsync(deviceCode, userCode)))
                .ToArray());

            Assert.Equal(1, claims.Count(took => took));
        }
    }

    [Fact]
    public async Task ACibaRequest_IsPolledAndUpdatedThenClaimedOnce()
    {
        var storage = NewCibaStorage();
        var request = NewCibaRequest();

        var requestId = await storage.StoreAsync(request, Lifetime);

        Assert.NotNull(await storage.TryGetAsync(requestId));
        Assert.NotNull(await storage.TryGetAsync(requestId));

        await storage.UpdateAsync(requestId, request, Lifetime);

        Assert.NotNull(await storage.TryRemoveAsync(requestId));
        Assert.Null(await storage.TryRemoveAsync(requestId));
    }

    [Fact]
    public async Task ManyInstancesClaimingOneCibaRequest_HandItToExactlyOne()
    {
        const int requests = 25;
        const int instances = 8;

        var storage = NewCibaStorage();

        for (var i = 0; i < requests; i++)
        {
            var request = NewCibaRequest();

            var requestId = await storage.StoreAsync(request, Lifetime);

            var claims = await Task.WhenAll(Enumerable
                .Range(0, instances)
                .Select(_ => Task.Run(() => storage.TryRemoveAsync(requestId)))
                .ToArray());

            Assert.Equal(1, claims.Count(claimed => claimed is not null));
        }
    }
}
