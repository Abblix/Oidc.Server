// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

public sealed partial class SharedSignalsTenantReleaseTests
{
    private const string MovedHost = "https://second.example.com";

    // The event a stream written after its tenant's release is logged under when its writer cannot delete it
    private const int ReleasedStreamNotDeleted = 10802;
    private const int WriteSentAgain = 10803;

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
    /// A stream its writer could not delete after the tenant's release is logged, naming the tenant with the creation
    /// it belonged to.
    /// </summary>
    [Theory]
    [InlineData("", "acme")]
    [InlineData("g2", "acme~g2")]
    public async Task AStreamItsWriterCannotDeleteAfterTheRelease_IsLogged(string generation, string named)
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        var time = new FakeTimeProvider();
        await store.AddAsync(TenantAt("acme", Host, generation), ct);
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

        var logged = Assert.Single(logs.Entries, entry => entry.EventId == ReleasedStreamNotDeleted);
        Assert.Equal(named, logged.Values["TenantId"]);
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

    /// <summary>
    /// A receiver deleting its declared stream while the store of the tenant's declared streams is replaced by a move
    /// has the stream deleted: the replaced store refuses the deletion, and it is made through the replacement.
    /// </summary>
    [Fact]
    public async Task AStreamDeletedWhileAMoveReplacesTheStore_IsDeleted()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = HeldStore.HoldingTheFirstCreate();
        await using var app = await StartWithADeclaredStreamAsync(store, new FakeTimeProvider(), streams.Store);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        var deleting = ClientOf(app, "acme").DeleteAsync($"/tenants/acme{StreamPath}?stream_id=alerts", ct);
        await streams.CreateEntered.WaitAsync(HeldFor, ct);

        var moved = await MoveWhileTheFirstStoreWritesAsync(app, store, catalog, ct);

        streams.Apply();
        using var deleted = await deleting;

        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.Empty(await StreamsOfAsync(app, moved, ct));
    }

    /// <summary>
    /// A receiver updating or replacing its declared stream, having read it before the tenant moved and writing after
    /// the store built for the move wrote the issuer the tenant moved to, keeps that issuer, has its own change applied,
    /// and is polled at an address under the issuer the tenant moved to, whether the stream polled before or the
    /// change asks for polling, and whether the move lands before the change minted its address or after it, while
    /// the write re-reads the stream.
    /// </summary>
    [Theory]
    [InlineData(false, false, true, 0)]
    [InlineData(false, true, true, 0)]
    [InlineData(true, true, true, 0)]
    [InlineData(true, true, false, 0)]
    [InlineData(false, true, true, 1)]
    [InlineData(true, true, true, 1)]
    [InlineData(true, true, false, 1)]
    public async Task AStreamChangedAcrossAMove_KeepsTheIssuerAndThePollAddressTheTenantMovedTo(
        bool replace,
        bool asksForPolling,
        bool declaredPolled,
        int readsBeforeTheMove)
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = HeldStore.HoldingTheFirstCreates(0);
        await using var app = await StartAsync(
            store,
            new FakeTimeProvider(),
            streams.Store,
            declare: server => server.AddConfiguredStreams(
                "acme",
                [
                    new ConfiguredStream
                    {
                        ReceiverId = ReceiverId,
                        StreamId = "alerts",
                        PushEndpointUrl = declaredPolled ? null : new Uri(PushEndpoint),
                    },
                ]));
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var first = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Equal(first.Issuer.OriginalString, await DeclaredIssuerAsync(app, first, ct));

        var read = streams.HoldTheNextRead(skip: readsBeforeTheMove);
        var client = ClientOf(app, "acme");
        var path = $"/tenants/acme{StreamPath}";
        var change = new UpdateStreamRequest
        {
            StreamId = "alerts",
            Delivery = asksForPolling ? new PollDeliveryMethod() : null,
            EventsRequested = replace ? [MembershipChanged] : null,
            Description = "updated",
        };
        var changing = replace ? client.PutAsJsonAsync(path, change, ct) : client.PatchAsJsonAsync(path, change, ct);
        await read.WaitAsync(HeldFor, ct);

        await MoveAsync(store, catalog, TenantAt("acme", MovedHost), ct);
        var moved = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Equal(moved.Issuer.OriginalString, await DeclaredIssuerAsync(app, moved, ct));

        streams.ReleaseTheRead();
        using var changed = await changing;

        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        var stream = Assert.Single(await StreamsOfAsync(app, moved, ct));
        Assert.Equal(moved.Issuer.OriginalString, stream.Configuration.Issuer);
        Assert.Equal("updated", stream.Configuration.Description);
        var poll = Assert.IsType<PollDeliveryMethod>(stream.Configuration.Delivery);
        Assert.StartsWith(moved.Issuer.OriginalString, Assert.IsType<Uri>(poll.EndpointUrl).OriginalString, StringComparison.Ordinal);
    }

    /// <summary>
    /// A stream a receiver created asks for polling again after its tenant moved, and is polled at an address under the
    /// issuer the tenant moved to rather than the one it left.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AStreamAskingForPollingAfterAMove_IsPolledWhereTheTenantMoved(bool replace)
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        await using var app = await StartAsync(store, new FakeTimeProvider());
        using var created = await ClientOf(app, "acme").PostAsJsonAsync(
            $"/tenants/acme{StreamPath}",
            new CreateStreamRequest { EventsRequested = [MembershipChanged] },
            ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var streamId = (await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct))!.StreamId;
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        await MoveAsync(store, catalog, TenantAt("acme", MovedHost), ct);
        var moved = (await catalog.FindByIdAsync("acme", ct))!;
        var client = app.GetTestClient();
        client.BaseAddress = new Uri(MovedHost);
        client.DefaultRequestHeaders.Add("X-Test-Issuer", moved.Issuer.OriginalString);
        client.DefaultRequestHeaders.Add("X-Test-Subject", ReceiverId);
        var change = new UpdateStreamRequest
        {
            StreamId = streamId,
            Delivery = new PollDeliveryMethod(),
            EventsRequested = [MembershipChanged],
        };
        var path = $"/tenants/acme{StreamPath}";
        using var changed = replace
            ? await client.PutAsJsonAsync(path, change, ct)
            : await client.PatchAsJsonAsync(path, change, ct);

        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);
        var poll = Assert.IsType<PollDeliveryMethod>(Assert.Single(await StreamsOfAsync(app, moved, ct)).Configuration.Delivery);
        Assert.StartsWith(moved.Issuer.OriginalString, Assert.IsType<Uri>(poll.EndpointUrl).OriginalString, StringComparison.Ordinal);
    }

    /// <summary>
    /// A receiver creating a stream while the store of the tenant's declared streams is replaced by a move has the
    /// stream created: the replaced store refuses the write, and it is made through the replacement.
    /// </summary>
    [Fact]
    public async Task AStreamCreatedWhileAMoveReplacesTheStore_IsCreated()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = HeldStore.HoldingTheFirstCreate();
        await using var app = await StartWithADeclaredStreamAsync(
            store, new FakeTimeProvider(), streams.Store, multipleStreamsPerReceiver: true);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        var creating = ClientOf(app, "acme").PostAsJsonAsync(
            $"/tenants/acme{StreamPath}",
            new CreateStreamRequest { EventsRequested = [MembershipChanged] },
            ct);
        await streams.CreateEntered.WaitAsync(HeldFor, ct);

        var moved = await MoveWhileTheFirstStoreWritesAsync(app, store, catalog, ct);

        streams.Apply();
        using var created = await creating;

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(2, (await StreamsOfAsync(app, moved, ct)).Count);
    }

    /// <summary>
    /// A receiver deleting its declared stream while a move replaces the store of the tenant's declared streams, and
    /// a move back replaces the replacement before the deletion passes it, has the stream deleted: each replaced store
    /// refuses the deletion, and it is made through the store the tenant is served at last.
    /// </summary>
    [Fact]
    public async Task AStreamDeletedWhileTwoMovesReplaceTheStore_IsDeleted()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        var streams = HeldStore.HoldingTheFirstCreates(2);
        var logs = new SignallingLoggerProvider();
        await using var app = await StartAsync(
            store, new FakeTimeProvider(), streams.Store, logs, declare: DeclareAStream);
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();

        var deleting = ClientOf(app, "acme").DeleteAsync($"/tenants/acme{StreamPath}?stream_id=alerts", ct);
        await streams.Entered(0).WaitAsync(HeldFor, ct);

        await MoveAsync(store, catalog, TenantAt("acme", MovedHost), ct);
        var replacing = StreamsOfAsync(app, (await catalog.FindByIdAsync("acme", ct))!, ct);
        await streams.Entered(1).WaitAsync(HeldFor, ct);

        // The deletion, refused by the first store, picks the store it is sent to next: the replacement
        var retried = logs.Next(WriteSentAgain);
        streams.Apply(0);
        await retried.WaitAsync(HeldFor, ct);

        await MoveAsync(store, catalog, TenantAt("acme"), ct);
        var back = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Single(await StreamsOfAsync(app, back, ct));

        streams.Apply(1);
        await replacing;
        using var deleted = await deleting;

        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.Empty(await StreamsOfAsync(app, back, ct));
    }

    /// <summary>
    /// A receiver deleting a stream nobody holds, in a tenant that declares streams, is told there is none: a refusal
    /// by the store the tenant is served at ends the retries.
    /// </summary>
    [Fact]
    public async Task AStreamNobodyHolds_IsAnsweredNotFound_InATenantDeclaringStreams()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        await using var app = await StartWithADeclaredStreamAsync(store, new FakeTimeProvider());

        // On a thread of its own, since retries that never end would spin on the store held in memory
        var deleting = Task.Run(
            () => ClientOf(app, "acme").DeleteAsync($"/tenants/acme{StreamPath}?stream_id=unknown", ct),
            ct);
        using var deleted = await deleting.WaitAsync(HeldFor, ct);

        Assert.Equal(HttpStatusCode.NotFound, deleted.StatusCode);
    }

    /// <summary>
    /// A declared poll stream of a moved tenant is polled at the issuer it moved to.
    /// </summary>
    [Fact]
    public async Task AMovedTenantsDeclaredPollStream_IsPolledAtTheIssuerItMovedTo()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new MemoryTenantStore();
        await store.AddAsync(TenantAt("acme"), ct);
        await using var app = await StartAsync(
            store,
            new FakeTimeProvider(),
            declare: server => server.AddConfiguredStreams(
                "acme", [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "alerts" }]));
        var catalog = app.Services.GetRequiredService<StoreTenantCatalog>();
        var first = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.StartsWith(first.Issuer.OriginalString, await PolledAtAsync(app, first, ct), StringComparison.Ordinal);

        await MoveAsync(store, catalog, TenantAt("acme", MovedHost), ct);
        var moved = (await catalog.FindByIdAsync("acme", ct))!;

        Assert.StartsWith(moved.Issuer.OriginalString, await PolledAtAsync(app, moved, ct), StringComparison.Ordinal);
    }

    private static async Task<string> PolledAtAsync(WebApplication app, TenantDefinition tenant, CancellationToken ct)
    {
        var delivery = Assert.IsType<PollDeliveryMethod>(
            Assert.Single(await StreamsOfAsync(app, tenant, ct)).Configuration.Delivery);
        return Assert.IsType<Uri>(delivery.EndpointUrl).OriginalString;
    }

    /// <summary>
    /// Moves the tenant while the first store of its declared streams is held in its write, and has the store the
    /// move builds write the declared stream at the issuer the tenant moved to.
    /// </summary>
    private static async Task<TenantDefinition> MoveWhileTheFirstStoreWritesAsync(
        WebApplication app,
        MemoryTenantStore store,
        StoreTenantCatalog catalog,
        CancellationToken ct)
    {
        await MoveAsync(store, catalog, TenantAt("acme", MovedHost), ct);
        var moved = (await catalog.FindByIdAsync("acme", ct))!;
        Assert.Equal(moved.Issuer.OriginalString, await DeclaredIssuerAsync(app, moved, ct));
        return moved;
    }

    private static Task<WebApplication> StartWithADeclaredStreamAsync(
        MemoryTenantStore store,
        FakeTimeProvider time,
        IStreamStore? streams = null,
        bool multipleStreamsPerReceiver = false)
        => StartAsync(
            store,
            time,
            streams,
            declare: DeclareAStream,
            multipleStreamsPerReceiver: multipleStreamsPerReceiver);

    private static void DeclareAStream(IOidcServerBuilder server)
        => server.AddConfiguredStreams(
            "acme",
            [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = "alerts", PushEndpointUrl = new Uri(PushEndpoint) }]);

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

    private static TenantDefinition TenantAt(string id, string host, string generation = "") => new()
    {
        Id = id,
        Generation = generation,
        Issuer = new Uri($"{host}/tenants/{id}"),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    /// <summary>
    /// A stream store in memory that holds each of its first creates until told to apply it, as a store slower than
    /// the release or the move would, and whose deletion honours the token it is handed, as a networked store's does.
    /// </summary>
    private sealed class HeldStore
    {
        private readonly TaskCompletionSource[] _entered;
        private readonly TaskCompletionSource[] _apply;
        private int _creates;
        private TaskCompletionSource? _readHeld;
        private TaskCompletionSource _readReleased = Signal();
        private int _readsToPass;

        private HeldStore(int held, CancellationTokenSource? cancelAfterCreate, bool deleteFails)
        {
            _entered = [..Enumerable.Range(0, held).Select(_ => Signal())];
            _apply = [..Enumerable.Range(0, held).Select(_ => Signal())];
            var inner = new InMemoryStreamStore();
            var store = new Mock<IStreamStore>(MockBehavior.Strict);
            store
                .Setup(s => s.TryCreateAsync(It.IsAny<StreamState>(), It.IsAny<CancellationToken>()))
                .Returns(async (StreamState stream, CancellationToken token) =>
                {
                    var create = Interlocked.Increment(ref _creates) - 1;
                    if (create >= held)
                        return await inner.TryCreateAsync(stream, token);

                    _entered[create].TrySetResult();
                    await _apply[create].Task.WaitAsync(HeldFor);
                    var created = await inner.TryCreateAsync(stream, CancellationToken.None);
                    if (cancelAfterCreate is not null)
                        await cancelAfterCreate.CancelAsync();

                    return created;
                });
            store
                .Setup(s => s.FindAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(async (string receiverId, string streamId, CancellationToken token) =>
                {
                    var found = await inner.FindAsync(receiverId, streamId, token);
                    if (Volatile.Read(ref _readHeld) is not null &&
                        Interlocked.Decrement(ref _readsToPass) < 0 &&
                        Interlocked.Exchange(ref _readHeld, null) is { } held)
                    {
                        var released = Volatile.Read(ref _readReleased);
                        held.TrySetResult();
                        await released.Task.WaitAsync(HeldFor);
                    }

                    return found;
                });
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
                    if (deleteFails && _apply[0].Task.IsCompleted)
                        throw new InvalidOperationException("The store lost its connection.");

                    token.ThrowIfCancellationRequested();
                    return inner.DeleteAsync(receiverId, streamId, token);
                });

            Store = store.Object;
        }

        public static HeldStore HoldingTheFirstCreate(
            CancellationTokenSource? cancelAfterCreate = null,
            bool deleteFails = false)
            => new(1, cancelAfterCreate, deleteFails);

        public static HeldStore HoldingTheFirstCreates(int held) => new(held, null, false);

        public IStreamStore Store { get; }

        public Task CreateEntered => Entered(0);

        public Task Entered(int create) => _entered[create].Task;

        /// <summary>
        /// Holds the read that follows <paramref name="skip"/> more reads, once it has read the store, until the
        /// <see cref="ReleaseTheRead"/> that follows; the task completes when that read is held.
        /// </summary>
        public Task HoldTheNextRead(int skip = 0)
        {
            var held = Signal();
            Volatile.Write(ref _readReleased, Signal());
            Volatile.Write(ref _readsToPass, skip);
            Volatile.Write(ref _readHeld, held);
            return held.Task;
        }

        public void ReleaseTheRead() => Volatile.Read(ref _readReleased).TrySetResult();

        public void Apply() => Apply(0);

        public void Apply(int create) => _apply[create].TrySetResult();

        private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <summary>
    /// Tells the test when the server next records an entry of one event id, as a write sent again through the
    /// transmitter the tenant is served now, which is recorded once that transmitter is chosen.
    /// </summary>
    private sealed class SignallingLoggerProvider : ILoggerProvider
    {
        private readonly Lock _gate = new();
        private (int EventId, TaskCompletionSource Signal)? _next;

        public ILogger CreateLogger(string categoryName) => new Signalling(this);

        public void Dispose()
        {
            // Nothing is held
        }

        public Task Next(int eventId)
        {
            var signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_gate)
                _next = (eventId, signal);
            return signal.Task;
        }

        private void Recorded(int eventId)
        {
            TaskCompletionSource? signal = null;
            lock (_gate)
            {
                if (_next is { } next && next.EventId == eventId)
                {
                    signal = next.Signal;
                    _next = null;
                }
            }

            signal?.TrySetResult();
        }

        private sealed class Signalling(SignallingLoggerProvider provider) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => provider.Recorded(eventId.Id);
        }
    }
}
