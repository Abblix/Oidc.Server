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
using Moq;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

public sealed partial class SharedSignalsTenantReleaseTests
{
    private const string MovedHost = "https://second.example.com";

    // The event a stream written after its tenant's release is logged under when its writer cannot delete it
    private const int ReleasedStreamNotDeleted = 10802;

    // How long a held write waits for the test to let it through, so a regression fails rather than hangs the run
    private static readonly TimeSpan HeldFor = TimeSpan.FromSeconds(30);

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
        var streams = HeldStore.HoldingTheFirstCreate();
        await using var app = await StartAsync(store, time, streams.Store);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        var creating = ClientOf(app, "acme").PostAsJsonAsync(
            $"/tenants/acme{StreamPath}",
            new CreateStreamRequest { EventsRequested = [MembershipChanged] },
            ct);
        await streams.CreateEntered.WaitAsync(HeldFor, ct);

        await ReleaseAsync(store, catalog, time, ct);

        streams.Apply();
        using var created = await creating;

        Assert.Empty(await streams.Store.ListAllAsync(ct));
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
        var streams = HeldStore.HoldingTheFirstCreate();
        await using var app = await StartWithADeclaredStreamAsync(store, time, streams.Store);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var acme = (await catalog.FindByIdAsync("acme", ct))!;

        var declaring = StreamsOfAsync(app, acme, ct);
        await streams.CreateEntered.WaitAsync(HeldFor, ct);

        await ReleaseAsync(store, catalog, time, ct);

        streams.Apply();
        await declaring;

        Assert.Empty(await streams.Store.ListAllAsync(ct));
    }

    /// <summary>
    /// A stream written while its tenant is released is deleted even when the caller that wrote it has given up, against
    /// a store whose deletion honours the token it is handed, as a networked store does.
    /// </summary>
    [Fact]
    public async Task AStreamWrittenWhileItsTenantIsReleased_IsDeleted_WhenItsCallerHasGivenUp()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        using var caller = new CancellationTokenSource();
        var streams = HeldStore.HoldingTheFirstCreate(cancelAfterCreate: caller);
        await using var app = await StartWithADeclaredStreamAsync(store, time, streams.Store);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var acme = (await catalog.FindByIdAsync("acme", ct))!;

        var declaring = StreamsOfAsync(app, acme, caller.Token);
        await streams.CreateEntered.WaitAsync(HeldFor, ct);

        await ReleaseAsync(store, catalog, time, ct);

        streams.Apply();

        // Whether the caller sees its own cancellation depends on where the read was when it gave up
        await Record.ExceptionAsync(() => declaring);

        Assert.Empty(await streams.Store.ListAllAsync(ct));
    }

    /// <summary>
    /// A stream its writer could not delete after the tenant's release is logged, naming it, since nothing else will
    /// delete it.
    /// </summary>
    [Fact]
    public async Task AStreamItsWriterCannotDeleteAfterTheRelease_IsLogged()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = HeldStore.HoldingTheFirstCreate(deleteFails: true);
        var logs = new RecordingLoggerProvider();
        await using var app = await StartAsync(store, time, streams.Store, logs);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        var creating = ClientOf(app, "acme").PostAsJsonAsync(
            $"/tenants/acme{StreamPath}",
            new CreateStreamRequest { EventsRequested = [MembershipChanged] },
            ct);
        await streams.CreateEntered.WaitAsync(HeldFor, ct);

        await ReleaseAsync(store, catalog, time, ct);

        streams.Apply();

        // The test server hands the failure the request ended in back to the client
        Assert.IsType<InvalidOperationException>(await Record.ExceptionAsync(() => creating));

        Assert.Contains(ReleasedStreamNotDeleted, logs.EventIds);
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
        await using var app = await StartWithADeclaredStreamAsync(store, new FakeTimeProvider());
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

    /// <summary>
    /// The declared streams of a tenant moved while its first store of them was still writing name the issuer it
    /// moved to: the store replaced by the move writes nothing over its replacement.
    /// </summary>
    [Fact]
    public async Task AStoreReplacedByAMoveMidWrite_LeavesTheIssuerTheTenantMovedTo()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = HeldStore.HoldingTheFirstCreate();
        await using var app = await StartWithADeclaredStreamAsync(store, new FakeTimeProvider(), streams.Store);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var first = (await catalog.FindByIdAsync("acme", ct))!;

        var replaced = StreamsOfAsync(app, first, ct);
        await streams.CreateEntered.WaitAsync(HeldFor, ct);

        await MoveAsync(store, catalog, TenantAt("acme", MovedHost), ct);
        var moved = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Equal(moved.Issuer.OriginalString, await DeclaredIssuerAsync(app, moved, ct));

        streams.Apply();
        await replaced;

        Assert.Equal(moved.Issuer.OriginalString, await DeclaredIssuerAsync(app, moved, ct));
    }

    /// <summary>
    /// A tenant with no generation, released and then served again under its id, has its declared streams written
    /// again, rather than finding the store of its earlier creation, whose streams the release deleted.
    /// </summary>
    [Fact]
    public async Task ATenantReleasedAndServedAgain_HasItsDeclaredStreamsWrittenAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme"), ct);
        await using var app = await StartWithADeclaredStreamAsync(store, time);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        Assert.Single(await StreamsOfAsync(app, (await catalog.FindByIdAsync("acme", ct))!, ct));

        await ReleaseAsync(store, catalog, time, ct);
        await store.AddAsync(TenantAt("acme"), ct);
        await catalog.RefreshAsync(ct);

        Assert.Single(await StreamsOfAsync(app, (await catalog.FindByIdAsync("acme", ct))!, ct));
    }

    private static Task<WebApplication> StartWithADeclaredStreamAsync(
        MemoryTenantStore store,
        FakeTimeProvider time,
        IStreamStore? streams = null)
        => StartAsync(
            store,
            time,
            streams,
            declare: server => server.AddConfiguredStreams(
                "acme",
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "alerts", PushEndpointUrl = new Uri(PushEndpoint) }]));

    private static async Task ReleaseAsync(
        MemoryTenantStore store,
        StoreTenantCatalog catalog,
        FakeTimeProvider time,
        CancellationToken ct)
    {
        var stored = Assert.Single(await store.ListAsync(ct));
        Assert.True(await store.RemoveAsync(stored.Tenant.Id, stored.Version, ct));
        await catalog.RefreshAsync(ct);
        time.Advance(new OidcOptions().RefreshTenantsEvery);
        await catalog.RefreshAsync(ct);
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
    /// A stream store in memory that holds its first create until told to apply it, as a store slower than the
    /// release or the move would, and whose deletion honours the token it is handed, as a networked store's does.
    /// </summary>
    private sealed class HeldStore
    {
        private readonly TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _apply = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _creates;

        private HeldStore(CancellationTokenSource? cancelAfterCreate, bool deleteFails)
        {
            var inner = new InMemoryStreamStore();
            var store = new Mock<IStreamStore>(MockBehavior.Strict);
            store
                .Setup(s => s.TryCreateAsync(It.IsAny<StreamState>(), It.IsAny<CancellationToken>()))
                .Returns(async (StreamState stream, CancellationToken token) =>
                {
                    if (Interlocked.Increment(ref _creates) != 1)
                        return await inner.TryCreateAsync(stream, token);

                    _entered.TrySetResult();
                    await _apply.Task.WaitAsync(HeldFor);
                    var created = await inner.TryCreateAsync(stream, CancellationToken.None);
                    if (cancelAfterCreate is not null)
                        await cancelAfterCreate.CancelAsync();

                    return created;
                });
            store
                .Setup(s => s.FindAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns((string receiverId, string streamId, CancellationToken token) =>
                    inner.FindAsync(receiverId, streamId, token));
            store
                .Setup(s => s.ListAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns((string receiverId, CancellationToken token) => inner.ListAsync(receiverId, token));
            store
                .Setup(s => s.ListAllAsync(It.IsAny<CancellationToken>()))
                .Returns((CancellationToken token) => inner.ListAllAsync(token));
            store
                .Setup(s => s.UpdateAsync(It.IsAny<StreamState>(), It.IsAny<CancellationToken>()))
                .Returns((StreamState stream, CancellationToken token) => inner.UpdateAsync(stream, token));
            store
                .Setup(s => s.DeleteAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns((string receiverId, string streamId, CancellationToken token) =>
                {
                    if (deleteFails && _apply.Task.IsCompleted)
                        throw new InvalidOperationException("The store lost its connection.");

                    token.ThrowIfCancellationRequested();
                    return inner.DeleteAsync(receiverId, streamId, token);
                });

            Store = store.Object;
        }

        public static HeldStore HoldingTheFirstCreate(
            CancellationTokenSource? cancelAfterCreate = null,
            bool deleteFails = false)
            => new(cancelAfterCreate, deleteFails);

        public IStreamStore Store { get; }

        public Task CreateEntered => _entered.Task;

        public void Apply() => _apply.TrySetResult();
    }
}
