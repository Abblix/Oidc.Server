// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Redis;
using Abblix.SharedSignals.Transmitter;
using Abblix.Tests.Shared;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using StackExchange.Redis;
using StreamConfiguration = Abblix.SharedSignals.Model.StreamConfiguration;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

// The Redis stream store under tenants, against an embedded Redis-compatible server
public sealed partial class SharedSignalsTenantReleaseTests
{
    /// <summary>
    /// The hash the transmitter's own streams are kept on, spelled out here rather than asked of the store, so a test
    /// and the store cannot move together.
    /// </summary>
    private static string TransmitterHash => $"Abblix.SharedSignals:RedisStreamStore:{Uri.EscapeDataString(Host)}";

    private static string PartitionHash(TenantDefinition tenant)
        => $"{TransmitterHash}:{Uri.EscapeDataString(TenantKey.PartitionOf(tenant))}";

    /// <summary>
    /// With two tenants holding streams, listing one tenant's streams and dispatching an event in it touch only the
    /// hash of that tenant's streams, as a recording connection shows, and releasing the tenant deletes that hash
    /// alone.
    /// </summary>
    [Fact]
    public async Task TheRedisStoreUnderTenants_ReadsAndWritesOnlyTheTenantsHash()
    {
        var ct = TestContext.Current.CancellationToken;
        using var garnet = new GarnetFixture();
        var calls = new ConcurrentQueue<(string Method, string Key)>();
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        await store.AddAsync(TenantAt("globex"), ct);
        await using var app = await StartOverRedisAsync(
            store, time, RecordingRedisProxy<IConnectionMultiplexer>.Over(garnet.Connection, calls));

        foreach (var tenantId in (string[])["acme", "globex"])
        {
            using var created = await ClientOf(app, tenantId).PostAsJsonAsync(
                $"/tenants/{tenantId}{StreamPath}", new CreateStreamRequest { EventsRequested = [MembershipChanged] }, ct);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var acme = (await catalog.FindByIdAsync("acme", ct))!;
        var globex = (await catalog.FindByIdAsync("globex", ct))!;
        var database = garnet.Connection.GetDatabase();
        Assert.Equal(1, await database.HashLengthAsync(PartitionHash(acme)));
        Assert.Equal(1, await database.HashLengthAsync(PartitionHash(globex)));
        Assert.False(await database.KeyExistsAsync(TransmitterHash));

        calls.Clear();
        var listed = await ClientOf(app, "acme").GetFromJsonAsync<StreamConfiguration[]>($"/tenants/acme{StreamPath}", ct);
        Assert.Single(listed!);
        Assert.Equal([PartitionHash(acme)], calls.Select(call => call.Key).Distinct().ToArray());
        Assert.Contains(calls, call => call.Method == nameof(IDatabase.HashGetAllAsync));

        calls.Clear();
        Assert.Equal(1, await DispatchAsync(app, acme, ct));
        Assert.Equal([PartitionHash(acme)], calls.Select(call => call.Key).Distinct().ToArray());

        var stored = (await store.ListAsync(ct)).Single(entry => entry.Tenant.Id == "acme");
        Assert.True(await store.RemoveAsync("acme", stored.Version, ct));
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);

        Assert.False(await database.KeyExistsAsync(PartitionHash(acme)));
        Assert.Equal(1, await database.HashLengthAsync(PartitionHash(globex)));
    }

    /// <summary>
    /// A store the host wraps around the Redis stream store without passing on its partitions would read every
    /// tenant's streams from where none of them are kept, so the server does not start.
    /// </summary>
    [Fact]
    public async Task AStoreWrappingTheRedisStoreWithoutItsPartitions_StopsTheServer()
    {
        using var garnet = new GarnetFixture();

        await Assert.ThrowsAsync<OptionsValidationException>(() => StartOverRedisAsync(
            new MemoryTenantStore(),
            new FakeTimeProvider(),
            garnet.Connection,
            streamStore: services => services
                .AddSharedSignalsRedisStreamStore()
                .AddSingleton<IStreamStore>(provider =>
                    new WrappingStreamStore(ActivatorUtilities.CreateInstance<RedisStreamStore>(provider)))));
    }

    /// <summary>
    /// A store the host wraps around the Redis stream store passing on its partitions serves each tenant's streams
    /// from that tenant's hash, as the Redis store does unwrapped.
    /// </summary>
    [Fact]
    public async Task AStoreWrappingTheRedisStoreWithItsPartitions_ReadsTheTenantsHash()
    {
        var ct = TestContext.Current.CancellationToken;
        using var garnet = new GarnetFixture();
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        await store.AddAsync(TenantAt("globex"), ct);
        var calls = new ConcurrentQueue<(string Method, string Key)>();

        await using var app = await StartOverRedisAsync(
            store,
            new FakeTimeProvider(),
            RecordingRedisProxy<IConnectionMultiplexer>.Over(garnet.Connection, calls),
            streamStore: services => services
                .AddSharedSignalsRedisStreamStore()
                .AddSingleton<IStreamStore>(provider =>
                    new PartitionedWrappingStreamStore(ActivatorUtilities.CreateInstance<RedisStreamStore>(provider))));
        foreach (var tenantId in (string[])["acme", "globex"])
        {
            using var created = await ClientOf(app, tenantId).PostAsJsonAsync(
                $"/tenants/{tenantId}{StreamPath}",
                new CreateStreamRequest { EventsRequested = [MembershipChanged] },
                ct);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        var acme = (await app.Services.GetRequiredService<StoreTenantCatalog>().FindByIdAsync("acme", ct))!;
        calls.Clear();
        var listed = await ClientOf(app, "acme").GetFromJsonAsync<StreamConfiguration[]>(
            $"/tenants/acme{StreamPath}",
            ct);

        Assert.Single(listed!);
        Assert.Equal([PartitionHash(acme)], calls.Select(call => call.Key).Distinct().ToArray());
    }

    /// <summary>
    /// The Redis stream store registered after the multi-tenant transmitter is refused once, for being registered
    /// there, and not a second time for the partitions the store every tenant shares then keeps none of.
    /// </summary>
    [Fact]
    public async Task TheRedisStoreRegisteredAfterTheTenantsTransmitter_IsRefusedForThatAlone()
    {
        using var garnet = new GarnetFixture();

        var refused = await Assert.ThrowsAsync<OptionsValidationException>(() => StartOverRedisAsync(
            new MemoryTenantStore(),
            new FakeTimeProvider(),
            garnet.Connection,
            streamStore: _ => { },
            afterSharedSignals: services => services.AddSharedSignalsRedisStreamStore()));

        Assert.Single(refused.Failures);
    }

    private static async Task<WebApplication> StartOverRedisAsync(
        MemoryTenantStore store,
        FakeTimeProvider time,
        IConnectionMultiplexer connection,
        Action<IServiceCollection>? streamStore = null,
        Action<IServiceCollection>? afterSharedSignals = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<TimeProvider>(time);
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        var server = builder.Services.AddOidcServices(_ => { });

        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Host,
            EventsSupported = [MembershipChanged],
            DefaultSubjectsMode = StreamSubjectsMode.All,
            PushDeliveryInterval = null,
        });
        builder.Services.AddSingleton(connection);
        (streamStore ?? (services => services.AddSharedSignalsRedisStreamStore()))(builder.Services);

        builder.Services.AddSingleton<ITenantStore>(store);
        builder.Services.AddSingleton<ITenantStoreWriter>(store);

        server.AddSharedSignals();
        afterSharedSignals?.Invoke(builder.Services);

        var app = builder.Build();

        // What a host's bearer authentication leaves behind: the receiver, and the issuer of its credentials
        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue("X-Test-Issuer", out var issuer))
            {
                Claim[] claims =
                [
                    new(IanaClaimTypes.Sub, context.Request.Headers["X-Test-Subject"].ToString()),
                    new(IanaClaimTypes.Iss, issuer.ToString()),
                ];
                context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
            }

            return next(context);
        });
        app.UseMultiTenancy();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }
}
