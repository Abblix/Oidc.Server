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
using Abblix.Oidc.Server.Features.DeviceAuthorization;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Redis;
using Abblix.Tests.Shared;
using Microsoft.Extensions.Logging.Abstractions;
using StackExchange.Redis;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// The sentence the package is sold on: exactly one caller redeems, however many INSTANCES are serving
/// the token endpoint.
/// </summary>
/// <remarks>
/// Every other row here runs its callers over one multiplexer, which the shared fixture's own remarks call
/// out: two callers sharing one are indistinguishable from one instance, so a test built that way measures
/// concurrency it has excluded. These rows each build a storage on a connection of its own, which is what
/// a second process has, and race them against each other.
/// <para>
/// What that buys is the ARRANGEMENT rather than extra detection: measured across every mutation of this
/// storage, each one that kills a row here also kills a single-connection one, because nothing in the
/// storage is per-instance except the script latch and no server the suite can start refuses the single
/// command. So these rows are what makes the sentence about several instances a measurement rather than an
/// extrapolation - and they are the rows that would speak first if anything per-instance were ever added.
/// </para>
/// </remarks>
public sealed class AcrossInstancesTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>, IDisposable
{
    private const int Instances = 4;
    private const int Rounds = 25;

    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private static readonly DateTimeOffset Instant = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// One connection per instance, kept for the class's lifetime so a round does not pay to open them.
    /// </summary>
    private readonly List<ConnectionMultiplexer> _connections = [];

    /// <summary>
    /// The prefix every instance in one test shares, so they are looking at the same records - which is the
    /// whole point, and which a per-storage prefix would quietly destroy.
    /// </summary>
    private readonly string _prefix = $"across:{Guid.NewGuid():N}:";

    private IEntityStorage[] Instances_() => Enumerable
        .Range(0, Instances)
        .Select(_ =>
        {
            var connection = garnet.CreateConnection();
            _connections.Add(connection);
            return (IEntityStorage)new RedisEntityStorage(
                connection,
                new JsonBinarySerializer(),
                TimeProvider.System,
                new RedisEntityStorageOptions { KeyPrefix = _prefix });
        })
        .ToArray();

    public void Dispose()
    {
        foreach (var connection in _connections)
            connection.Dispose();
    }

    private static AuthorizedGrant NewGrant() => new(
        new AuthSession("a-subject", "a-session", Instant, "a-provider"),
        new AuthorizationContext("a-client", ["openid"], null));

    private sealed class StubCodeGenerator : IAuthorizationCodeGenerator
    {
        public string GenerateAuthorizationCode() => Guid.NewGuid().ToString("N");
    }

    [Fact]
    public async Task SeveralInstancesRedeemingOneAuthorizationCode_HandTheGrantToExactlyOne()
    {
        var services = Instances_()
            .Select(storage => new AuthorizationCodeService(
                new StubCodeGenerator(), storage, new EntityStorageKeyFactory()))
            .ToArray();

        for (var round = 0; round < Rounds; round++)
        {
            var code = await services[0].GenerateAuthorizationCodeAsync(NewGrant(), Lifetime);

            var redemptions = await Task.WhenAll(services
                .Select(service => Task.Run(() => service.RemoveAuthorizationCodeAsync(code)))
                .ToArray());

            Assert.Equal(1, redemptions.Count(result => result.TryGetSuccess(out _)));
        }
    }

    [Fact]
    public async Task SeveralInstancesClaimingOneDeviceCode_TellExactlyOneItTookIt()
    {
        var storages = Instances_()
            .Select(storage => new DeviceAuthorizationStorage(
                NullLogger<DeviceAuthorizationStorage>.Instance,
                storage,
                new EntityStorageKeyFactory(),
                TimeProvider.System))
            .ToArray();

        for (var round = 0; round < Rounds; round++)
        {
            var deviceCode = Guid.NewGuid().ToString("N");
            var userCode = Guid.NewGuid().ToString("N")[..8];

            await storages[0].StoreAsync(
                deviceCode,
                new DeviceAuthorizationRequest("a-client", ["openid"], null, userCode),
                Lifetime);

            var claims = await Task.WhenAll(storages
                .Select(storage => Task.Run(() => storage.TryRemoveAsync(deviceCode, userCode)))
                .ToArray());

            Assert.Equal(1, claims.Count(took => took));
        }
    }

    /// <summary>
    /// One instance writes and a different one reads it back, which is what makes the prefix and the
    /// framing a shared agreement rather than each instance's private habit.
    /// </summary>
    [Fact]
    public async Task WhatOneInstanceWrote_AnotherReadsAndTakes()
    {
        var storages = Instances_();
        var code = Guid.NewGuid().ToString("N");

        await storages[0].SetAsync(
            code,
            NewGrant(),
            new StorageOptions { AbsoluteExpirationRelativeToNow = Lifetime });

        Assert.NotNull(await storages[1].GetAsync<AuthorizedGrant>(code, removeOnRetrieval: false));
        Assert.NotNull(await storages[2].GetAsync<AuthorizedGrant>(code, removeOnRetrieval: true));
        Assert.Null(await storages[3].GetAsync<AuthorizedGrant>(code, removeOnRetrieval: false));
    }
}
