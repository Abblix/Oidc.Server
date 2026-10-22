// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

public sealed partial class SharedSignalsTenantReleaseTests
{
    private const string MovedHost = "https://second.example.com";

    /// <summary>
    /// A stream whose write was still under way when its tenant was released, and so is missing from the listing the
    /// release deletes, is deleted by the writer once the write completes.
    /// </summary>
    [Fact]
    public async Task AStreamWrittenWhileItsTenantIsReleased_IsLeftInNoStore()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = new HeldCreateStore(new InMemoryStreamStore());
        await using var app = await StartAsync(store, time, streams);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        var creating = ClientOf(app, "acme").PostAsJsonAsync(
            $"/tenants/acme{StreamPath}",
            new CreateStreamRequest { EventsRequested = [MembershipChanged] },
            ct);
        await streams.CreateEntered.WaitAsync(ct);

        var stored = Assert.Single(await store.ListAsync(ct));
        Assert.True(await store.RemoveAsync("acme", stored.Version, ct));
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);

        streams.Apply();
        using var created = await creating;

        Assert.Empty(await streams.ListAllAsync(ct));
    }

    /// <summary>
    /// A declared stream whose first write was still under way when its tenant was released is deleted by the writer
    /// once the write completes.
    /// </summary>
    [Fact]
    public async Task ADeclaredStreamWrittenWhileItsTenantIsReleased_IsLeftInNoStore()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = new HeldCreateStore(new InMemoryStreamStore());
        await using var app = await StartAsync(
            store,
            time,
            streams,
            declare: server => server.AddConfiguredStreams(
                "acme",
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "alerts", PushEndpointUrl = new Uri(PushEndpoint) }]));
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var acme = (await catalog.FindByIdAsync("acme", ct))!;

        var declaring = StreamsOfAsync(app, acme, ct);
        await streams.CreateEntered.WaitAsync(ct);

        var stored = Assert.Single(await store.ListAsync(ct));
        Assert.True(await store.RemoveAsync("acme", stored.Version, ct));
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);

        streams.Apply();
        await declaring;

        Assert.Empty(await streams.ListAllAsync(ct));
    }

    /// <summary>
    /// The streams a tenant declares name the issuer it is served at: after a move the one it moved to, after a move
    /// back the first one again, and a request still holding the definition from before a move does not bring the
    /// issuer it left back.
    /// </summary>
    [Fact]
    public async Task AMovedTenantsDeclaredStreams_NameTheIssuerItIsServedAt()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        await using var app = await StartAsync(
            store,
            new FakeTimeProvider(),
            declare: server => server.AddConfiguredStreams(
                "acme",
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "alerts", PushEndpointUrl = new Uri(PushEndpoint) }]));
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        var first = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Equal(first.Issuer.OriginalString, await DeclaredIssuerAsync(app, first, ct));

        await MoveAsync(store, catalog, TenantAt("acme", MovedHost), ct);
        var moved = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Equal(moved.Issuer.OriginalString, await DeclaredIssuerAsync(app, moved, ct));
        Assert.Equal(moved.Issuer.OriginalString, await DeclaredIssuerAsync(app, first, ct));

        await MoveAsync(store, catalog, TenantAt("acme"), ct);
        Assert.Equal(first.Issuer.OriginalString, await DeclaredIssuerAsync(app, moved, ct));
    }

    private static async Task<string> DeclaredIssuerAsync(WebApplication app, TenantDefinition tenant, CancellationToken ct)
        => Assert.Single(await StreamsOfAsync(app, tenant, ct)).Configuration.Issuer;

    private static async Task MoveAsync(
        MemoryTenantStore store,
        StoreTenantCatalog catalog,
        TenantDefinition to,
        CancellationToken ct)
    {
        var stored = Assert.Single(await store.ListAsync(ct));
        Assert.NotNull(await store.UpdateAsync(to, stored.Version, ct));
        await catalog.RefreshAsync(ct);
    }

    private static TenantDefinition TenantAt(string id, string host) => new()
    {
        Id = id,
        Issuer = new Uri($"{host}/tenants/{id}"),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    /// <summary>
    /// A stream store that holds each create until told to apply it, as a store slower than the release would.
    /// </summary>
    private sealed class HeldCreateStore(IStreamStore inner) : IStreamStore
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _apply = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task CreateEntered => _entered.Task;

        public void Apply() => _apply.TrySetResult();

        public async Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        {
            _entered.TrySetResult();
            await _apply.Task.WaitAsync(cancellationToken);
            return await inner.TryCreateAsync(stream, cancellationToken);
        }

        public Task<StreamState?> FindAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.FindAsync(receiverId, streamId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAsync(string receiverId, CancellationToken cancellationToken = default)
            => inner.ListAsync(receiverId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
            => inner.ListAllAsync(cancellationToken);

        public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => inner.UpdateAsync(stream, cancellationToken);

        public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.DeleteAsync(receiverId, streamId, cancellationToken);
    }
}
