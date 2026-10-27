// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Telemetry;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Abblix.Oidc.Server.Features.Consents;


namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A Shared Signals transmitter on a running multi-tenant server, where two tenants' receivers carry the same
/// identifier: nothing but the tenant tells their streams apart, so what one tenant's receiver set up must not reach
/// the other, and each tenant must answer as itself.
/// </summary>
public sealed class SharedSignalsTenantIsolationTests
{
    private const string Host = "https://auth.example.com";
    private const string Acme = "/tenants/acme";
    private const string Globex = "/tenants/globex";
    private const string StreamPath = "/ssf/stream";
    private const string ReceiverId = "https://receiver.example.com";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";
    private const string JwksPath = "/.well-known/jwks";
    private const string SubjectHeader = "X-Test-Subject";
    private const string IssuerHeader = "X-Test-Issuer";

    [SuppressMessage("Minor Code Smell", "S1075",
        Justification = "The push endpoint a test receiver registers; the recording handler answers it.")]
    private const string PushEndpoint = "https://receiver.example.com/events";
    private const string StreamId = "alerts";

    /// <summary>How long a test waits for a delivery it holds to reach the receiver.</summary>
    private static readonly TimeSpan HeldFor = TimeSpan.FromSeconds(30);

    /// <summary>
    /// A stream acme's receiver creates is acme's alone: globex's receiver, under the same identifier, lists none,
    /// an event dispatched in globex reaches nothing, and the event dispatched in acme is polled from acme's own
    /// address, signed as acme with a key acme publishes and globex does not.
    /// </summary>
    [Fact]
    public async Task AStream_ItsEventsAndItsAddress_StayWithItsTenant()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var acme = ClientOf(app, Host + Acme);
        var globex = ClientOf(app, Host + Globex);

        using var created = await acme.PostAsJsonAsync(
            Acme + StreamPath, new CreateStreamRequest { EventsRequested = [MembershipChanged] }, ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var stream = (await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct))!;
        Assert.Equal(Host + Acme, stream.Issuer);
        var poll = Assert.IsType<Uri>(Assert.IsType<PollDeliveryMethod>(stream.Delivery).EndpointUrl);
        Assert.StartsWith(Host + Acme + "/ssf/poll/", poll.AbsoluteUri, StringComparison.Ordinal);

        Assert.Single((await acme.GetFromJsonAsync<StreamConfiguration[]>(Acme + StreamPath, ct))!);
        Assert.Empty((await globex.GetFromJsonAsync<StreamConfiguration[]>(Globex + StreamPath, ct))!);

        Assert.Equal(0, await DispatchAsync(app, "globex", ct));
        Assert.Equal(1, await DispatchAsync(app, "acme", ct));

        using var polled = await acme.PostAsJsonAsync(poll, new PollRequest { ReturnImmediately = true }, ct);
        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
        var token = Assert.Single((await polled.Content.ReadFromJsonAsync<PollResponse>(ct))!.Sets).Value;
        Assert.Equal(Host + Acme, IssuerOf(token));

        // Verified against the key set each tenant's document advertises, as a receiver would
        Assert.True(VerifiesAgainst(token, await KeySetOfAsync(acme, Acme, ct)));
        Assert.False(VerifiesAgainst(token, await KeySetOfAsync(globex, Globex, ct)));
    }

    /// <summary>
    /// A stream acme's receiver created is not found by globex's receiver under the same identifier: reading,
    /// updating and deleting it there answer 404, and it is still acme's afterwards.
    /// </summary>
    [Fact]
    public async Task AStreamOfOneTenant_IsNotFoundAtAnother()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var acme = ClientOf(app, Host + Acme);
        var globex = ClientOf(app, Host + Globex);

        using var created = await acme.PostAsJsonAsync(
            Acme + StreamPath, new CreateStreamRequest { EventsRequested = [MembershipChanged] }, ct);
        var streamId = (await created.Content.ReadFromJsonAsync<StreamConfiguration>(ct))!.StreamId;
        var addressed = $"{Globex}{StreamPath}?stream_id={streamId}";

        using var read = await globex.GetAsync(addressed, ct);
        using var updated = await globex.PatchAsJsonAsync(
            Globex + StreamPath, new UpdateStreamRequest { StreamId = streamId, Description = "taken" }, ct);
        using var deleted = await globex.DeleteAsync(addressed, ct);

        Assert.Equal(
            [HttpStatusCode.NotFound, HttpStatusCode.NotFound, HttpStatusCode.NotFound],
            [read.StatusCode, updated.StatusCode, deleted.StatusCode]);
        Assert.Single((await acme.GetFromJsonAsync<StreamConfiguration[]>(Acme + StreamPath, ct))!);
    }

    /// <summary>
    /// Each tenant's configuration document is reached where SSF 1.0 Section 7.2 puts it for that tenant's issuer,
    /// and names that issuer, its key set and its own management address.
    /// </summary>
    [Theory]
    [InlineData(Acme)]
    [InlineData(Globex)]
    public async Task TheConfigurationDocument_IsEachTenantsOwn(string tenant)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        var document = await ClientOf(app, Host + tenant).GetFromJsonAsync<TransmitterConfiguration>(
            "/.well-known/ssf-configuration" + tenant, ct);

        Assert.Equal(Host + tenant, document!.Issuer);
        Assert.Equal(new Uri(Host + tenant + JwksPath), document.JwksUri);
        Assert.Equal(new Uri(Host + tenant + StreamPath), document.ConfigurationEndpoint);
    }

    /// <summary>
    /// A request reaching no tenant reaches no transmitter, and is answered 404 rather than failing.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/ssf-configuration")]
    [InlineData(StreamPath)]
    public async Task ARequestReachingNoTenant_IsNotFound(string path)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        using var response = await ClientOf(app, Host + Acme).GetAsync(path, ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// A stream store the host registers after the transmitter's own is the one every tenant's streams are kept in,
    /// as it is the one the container resolves.
    /// </summary>
    [Fact]
    public async Task AStoreTheHostRegistersAfterTheTransmittersOwn_HoldsTheStreams()
    {
        var ct = TestContext.Current.CancellationToken;
        var hosts = new InMemoryStreamStore();
        await using var app = await StartAsync(beforeMultiTenancy: services => services.AddSingleton<IStreamStore>(hosts));

        using var created = await ClientOf(app, Host + Acme).PostAsJsonAsync(
            Acme + StreamPath, new CreateStreamRequest { EventsRequested = [MembershipChanged] }, ct);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Single(await hosts.ListAllAsync(ct));
    }

    /// <summary>
    /// A poll handler resolved where no tenant is served refuses once it reaches the queued events, rather than
    /// answering from a queue no tenant owns.
    /// </summary>
    [Fact]
    public async Task APollHandlerResolvedWhereNoTenantIsServed_RefusesOnceUsed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var handler = app.Services.GetRequiredService<PollEndpointHandler>();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => handler.HandleAsync(AcmesStream(), new PollRequest { ReturnImmediately = true }, ct));
    }

    /// <summary>
    /// A poll handler a host kept from acme's request refuses to read the queued events while globex is served,
    /// rather than answering globex's caller from acme's queue.
    /// </summary>
    [Fact]
    public async Task APollHandlerKeptFromAnotherTenantsRequest_RefusesOnceUsed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var catalog = app.Services.GetRequiredService<ITenantCatalog>();

        PollEndpointHandler kept;
        using (TenantScope.Enter((await catalog.FindByIdAsync("acme", ct))!))
            kept = app.Services.GetRequiredService<PollEndpointHandler>();

        using var scope = TenantScope.Enter((await catalog.FindByIdAsync("globex", ct))!);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => kept.HandleAsync(AcmesStream(), new PollRequest { ReturnImmediately = true }, ct));
    }

    /// <summary>
    /// A poll stream of acme's receiver, as the store hands it to the poll handler.
    /// </summary>
    private static StreamState AcmesStream() => new()
    {
        ReceiverId = ReceiverId,
        Status = StreamStatuses.Enabled,
        SubjectsMode = StreamSubjectsMode.All,
        Configuration = new StreamConfiguration
        {
            StreamId = StreamId,
            Issuer = Host + Acme,
            Audiences = [ReceiverId],
            EventsDelivered = [MembershipChanged],
            Delivery = new PollDeliveryMethod(new Uri(Host + Acme + StreamPath)),
        },
    };

    /// <summary>
    /// A receiver whose credentials globex issued, with the same identifier as acme's receiver, presents them under
    /// acme's address and is refused as holding a token that is invalid here, so it cannot reach acme's streams.
    /// </summary>
    [Fact]
    public async Task AReceiverOfAnotherTenant_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        using var response = await ClientOf(app, Host + Globex).GetAsync(Acme + StreamPath, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("error=\"invalid_token\"", Assert.Single(response.Headers.WwwAuthenticate).Parameter);
    }

    /// <summary>
    /// The refusals before any stream is reached travel uncacheable, as every other management answer does.
    /// </summary>
    [Theory]
    [InlineData(StreamPath, Host + Acme)]
    [InlineData(Acme + StreamPath, Host + Globex)]
    public async Task ARefusalOfTheManagementSurface_IsNotCached(string path, string issuer)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();

        using var response = await ClientOf(app, issuer).GetAsync(path, ct);

        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    /// <summary>
    /// Push delivery runs on a timer, outside any request, and still delivers each tenant's events from inside that
    /// tenant: the event dispatched in acme reaches acme's receiver once, signed as acme, and globex's stream at the
    /// same address receives nothing. What the transmitter records of the event names acme too.
    /// </summary>
    [Fact]
    public async Task PushDelivery_DeliversEachTenantsEventsFromInsideIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var receiver = new RecordingReceiver();
        // The receiver stands where the network would, behind the client each tenant's sender posts through
        await using var app = await StartAsync(beforeMultiTenancy: services => services
            .AddHttpClient(nameof(PushDeliverySender))
            .ConfigurePrimaryHttpMessageHandler(() => receiver));

        foreach (var tenant in (string[])[Acme, Globex])
        {
            using var created = await ClientOf(app, Host + tenant).PostAsJsonAsync(
                tenant + StreamPath,
                new CreateStreamRequest
                {
                    EventsRequested = [MembershipChanged],
                    Delivery = new PushDeliveryMethod(new Uri(PushEndpoint)),
                },
                ct);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        var meters = app.Services.GetRequiredService<IMeterFactory>();
        var tenants = new ConcurrentQueue<(string Instrument, object? Tenant)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Scope == meters && instrument.Meter.Name == SharedSignalsTelemetry.SourceName)
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) => tenants.Enqueue(
            (instrument.Name, tags.ToArray().SingleOrDefault(tag => tag.Key == SharedSignalsTags.Tenant).Value)));
        listener.Start();

        Assert.Equal(1, await DispatchAsync(app, "acme", ct));
        await app.Services.GetRequiredService<IPushDeliverySweep>().SweepAsync(ct);

        var token = Assert.Single(receiver.Tokens);
        Assert.Equal(Host + Acme, IssuerOf(token));

        // Signed on the sweep rather than in the request that queued it, so the key is the one the sweep entered
        Assert.True(VerifiesAgainst(token, await KeySetOfAsync(ClientOf(app, Host + Acme), Acme, ct)));
        Assert.False(VerifiesAgainst(token, await KeySetOfAsync(ClientOf(app, Host + Globex), Globex, ct)));

        (string, object?)[] expected =
            [(SharedSignalsMetrics.EventsTransmitted, "acme"), (SharedSignalsMetrics.PushDeliveries, "acme")];
        Assert.Equal(expected, tenants.ToArray());
    }

    /// <summary>
    /// A part registered after the transmitter was made per tenant would serve every tenant alike, so the server
    /// does not start.
    /// </summary>
    [Theory]
    [InlineData(typeof(IStreamStore), typeof(InMemoryStreamStore))]
    [InlineData(typeof(ITransmitterIdentity), typeof(OptionsTransmitterIdentity))]
    [InlineData(typeof(IPushDeliverySweep), typeof(PushDeliverySweep))]
    public async Task APartReplacedAfterwards_StopsTheServer(Type service, Type replacement)
        => await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(
            afterSharedSignals: services =>
                services.Replace(ServiceDescriptor.Singleton(service, replacement))));

    /// <summary>
    /// Each tenant's addresses are the options' paths under the tenant's issuer, so an issuer naming a path of its
    /// own, or a key set on another host, stops the server.
    /// </summary>
    [Theory]
    [InlineData(Host + "/ssf-issuer", Host + "/ssf-issuer" + JwksPath)]
    [InlineData(Host, "https://keys.example.net" + JwksPath)]
    [InlineData(Host, JwksPath)]
    public async Task AnAddressNoTenantCanServe_StopsTheServer(string issuer, string jwksUri)
        => await Assert.ThrowsAsync<OptionsValidationException>(
            () => StartAsync(issuer, new Uri(jwksUri, UriKind.RelativeOrAbsolute)));

    /// <summary>
    /// Streams declared for the whole server belong to no tenant's receivers, so the server does not start with them,
    /// whether they are delivered by push or polled.
    /// </summary>
    [Theory]
    [InlineData(PushEndpoint)]
    [InlineData(null)]
    public async Task DeclaredStreams_StopTheServer(string? pushEndpoint)
    {
        var refusal = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(
            beforeMultiTenancy: services => services.AddSharedSignalsConfiguredStreams(
                [new ConfiguredStream
                {
                    ReceiverId = ReceiverId,
                    StreamId = StreamId,
                    PushEndpointUrl = pushEndpoint is null ? null : new Uri(pushEndpoint),
                }])));

        Assert.Single(refusal.Failures);
    }

    /// <summary>
    /// A tenant's declared streams that no request could be served from - one declared twice, one with no stream id -
    /// stop the server when it starts rather than on the first request to that tenant, and the refusal names the
    /// tenant.
    /// </summary>
    [Theory]
    [InlineData(StreamId, StreamId)]
    [InlineData(StreamId, "")]
    public async Task ATenantsDeclaredStreamsNoRequestCouldServe_StopTheServer(string first, string second)
    {
        var refusal = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(
            declare: server => server.AddConfiguredStreams(
                "acme",
                [
                    new ConfiguredStream { ReceiverId = ReceiverId, StreamId = first, PushEndpointUrl = new Uri(PushEndpoint) },
                    new ConfiguredStream { ReceiverId = ReceiverId, StreamId = second, PushEndpointUrl = new Uri(PushEndpoint) },
                ])));

        Assert.Contains("acme", Assert.Single(refusal.Failures));
    }

    /// <summary>
    /// A host that maps its endpoints while it starts, as one configuring its pipeline in <c>Configure</c>, has a poll
    /// address only from then on, and a tenant's stream delivered by polling is judged after that: the host starts and
    /// the stream is served with the tenant's poll address.
    /// </summary>
    [Fact]
    public async Task ADeclaredPollStream_OfAHostMappingItsEndpointsWhileItStarts_IsServed()
    {
        var ct = TestContext.Current.CancellationToken;
        await TestLicense.Loaded;
        using var host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddDistributedMemoryCache();
                    services.AddMemoryCache();
                    services.AddAuthentication().AddCookie();
                    services.AddAuthorization();
                    services.AddConsentGrantedForEveryClient();
                    var server = services.AddOidcServices(options => options.Tenants.Add(TenantAt("acme", Acme)));
                    services.AddSecurityEvents();
                    services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
                    {
                        Issuer = Host,
                        JwksUri = new Uri(Host + JwksPath),
                        EventsSupported = [MembershipChanged],
                        DefaultSubjectsMode = StreamSubjectsMode.All,
                    });
                    server.AddSharedSignals();
                    server.AddConfiguredStreams("acme", [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = StreamId }]);
                })
                .Configure(app =>
                {
                    app.UseMultiTenancy();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapOidcEndpoints();
                        endpoints.MapSharedSignalsTransmitterEndpoints();
                    });
                }))
            .Build();

        await host.StartAsync(ct);

        var tenant = (await host.Services.GetRequiredService<ITenantCatalog>().FindByIdAsync("acme", ct))!;
        using (TenantScope.Enter(tenant))
        {
            var stream = Assert.Single(await host.Services.GetRequiredService<IStreamStore>().ListAllAsync(ct));
            var poll = Assert.IsType<PollDeliveryMethod>(stream.Configuration.Delivery);
            Assert.StartsWith(Host + Acme, Assert.IsType<Uri>(poll.EndpointUrl).OriginalString, StringComparison.Ordinal);
        }

        await host.StopAsync(ct);
    }

    /// <summary>
    /// Streams declared for a tenant the server's settings do not declare would never be served, so the server does
    /// not start.
    /// </summary>
    [Fact]
    public async Task StreamsDeclaredForATenantTheServerDoesNotServe_StopTheServer()
    {
        var refusal = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(
            declare: server => server.AddConfiguredStreams(
                "initech",
                [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = StreamId, PushEndpointUrl = new Uri(PushEndpoint) }])));

        Assert.Contains("initech", Assert.Single(refusal.Failures));
    }

    /// <summary>
    /// The streams a tenant declares are its receiver's, as created through the management API would be, and no other
    /// tenant's receiver finds them.
    /// </summary>
    [Fact]
    public async Task ATenantsDeclaredStreams_AreItsReceiversAndNoOneElses()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync(declare: server => server.AddConfiguredStreams(
            "acme",
            [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = StreamId, PushEndpointUrl = new Uri(PushEndpoint) }]));

        var acme = await ClientOf(app, Host + Acme).GetFromJsonAsync<StreamConfiguration[]>(Acme + StreamPath, ct);
        var globex = await ClientOf(app, Host + Globex).GetFromJsonAsync<StreamConfiguration[]>(Globex + StreamPath, ct);

        var declared = Assert.Single(acme!);
        Assert.Equal(StreamId, declared.StreamId);
        Assert.Equal(Host + Acme, declared.Issuer);
        Assert.Empty(globex!);
    }

    /// <summary>
    /// Two tenants may declare a stream under the same receiver and stream identifiers, since the operator names them:
    /// each stream still queues its own tenant's events alone, so an event dispatched in acme is polled from acme's
    /// stream and globex's receiver, polling its own, finds nothing.
    /// </summary>
    [Fact]
    public async Task StreamsTwoTenantsDeclareUnderOneName_QueueEachTenantsEventsApart()
    {
        var ct = TestContext.Current.CancellationToken;
        ConfiguredStream[] declared =
            [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = StreamId, EventsRequested = [MembershipChanged] }];
        await using var app = await StartAsync(declare: server => server
            .AddConfiguredStreams("acme", declared)
            .AddConfiguredStreams("globex", declared));
        var acme = ClientOf(app, Host + Acme);
        var globex = ClientOf(app, Host + Globex);

        Assert.Equal(1, await DispatchAsync(app, "acme", ct));

        var atGlobex = await PollAsync(globex, Globex, ct);
        Assert.Empty(atGlobex);

        var token = Assert.Single(await PollAsync(acme, Acme, ct));
        Assert.Equal(Host + Acme, IssuerOf(token));
    }

    /// <summary>
    /// Two instances sweeping at once, the first holding its claim on acme's stream while it delivers, leave globex's
    /// stream of the same identifiers to the second: each tenant's claims on its streams are its own.
    /// </summary>
    [Fact]
    public async Task ADeliveryInProgress_DoesNotHoldAnotherTenantsStreamOfTheSameName()
    {
        var ct = TestContext.Current.CancellationToken;
        var receiver = new HoldingReceiver(Host + Acme);
        ConfiguredStream[] declared =
        [
            new ConfiguredStream
            {
                ReceiverId = ReceiverId,
                StreamId = StreamId,
                EventsRequested = [MembershipChanged],
                PushEndpointUrl = new Uri(PushEndpoint),
            },
        ];
        await using var app = await StartAsync(
            beforeMultiTenancy: services => services
                .AddHttpClient(nameof(PushDeliverySender))
                .ConfigurePrimaryHttpMessageHandler(() => receiver),
            declare: server => server
                .AddConfiguredStreams("acme", declared)
                .AddConfiguredStreams("globex", declared));
        var sweep = app.Services.GetRequiredService<IPushDeliverySweep>();

        Assert.Equal(1, await DispatchAsync(app, "acme", ct));
        var delivering = sweep.SweepAsync(ct);
        try
        {
            await receiver.Held.WaitAsync(HeldFor, ct);

            // Queued once the first sweep holds acme's claim, so only the second sweep can deliver it
            Assert.Equal(1, await DispatchAsync(app, "globex", ct));
            await sweep.SweepAsync(ct);

            var token = Assert.Single(receiver.Tokens);
            Assert.Equal(Host + Globex, IssuerOf(token));
        }
        finally
        {
            receiver.Release();
            await delivering;
        }
    }

    /// <summary>
    /// An event dispatcher a host kept from acme's request refuses to dispatch where acme is not served, as for
    /// globex's event in globex's request or in a job of the host's that serves no tenant, rather than queueing the
    /// event on acme's streams for acme's receivers.
    /// </summary>
    [Theory]
    [InlineData("globex")]
    [InlineData(null)]
    public async Task ADispatcherKeptFromAnotherTenantsRequest_RefusesToDispatch(string? servedAt)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var catalog = app.Services.GetRequiredService<ITenantCatalog>();

        EventDispatcher kept;
        using (TenantScope.Enter((await catalog.FindByIdAsync("acme", ct))!))
            kept = app.Services.GetRequiredService<EventDispatcher>();

        using var scope = servedAt is null ? null : TenantScope.Enter((await catalog.FindByIdAsync(servedAt, ct))!);
        await Assert.ThrowsAsync<InvalidOperationException>(() => kept.DispatchAsync(
            new SecurityEventDescriptor { EventType = MembershipChanged, Subject = new EmailSubject("jdoe@example.com") },
            ct));
    }

    /// <summary>
    /// The signer of queued events a host kept from acme's request refuses to sign in globex's request, rather than
    /// signing with acme's keys.
    /// </summary>
    [Fact]
    public async Task ASignerKeptFromAnotherTenantsRequest_RefusesToSign()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync();
        var catalog = app.Services.GetRequiredService<ITenantCatalog>();

        QueuedEventSigner kept;
        using (TenantScope.Enter((await catalog.FindByIdAsync("acme", ct))!))
            kept = app.Services.GetRequiredService<QueuedEventSigner>();

        var queued = new OutboxItem("event-1", CompactToken: null, Unsigned: QueuedEventSigner.ToQueued(
            new SecurityEventToken(new JsonWebToken())));
        using var scope = TenantScope.Enter((await catalog.FindByIdAsync("globex", ct))!);
        await Assert.ThrowsAsync<InvalidOperationException>(() => kept.SignAsync(queued, ct));
    }

    /// <summary>
    /// A tenant whose key the host's own catalog rotates signs its events with the new key from then on, an event
    /// queued before the rotation included.
    /// </summary>
    [Fact]
    public async Task AKeyRotatedInTheHostsCatalog_SignsTheEventsPolledAfterIt()
    {
        var ct = TestContext.Current.CancellationToken;
        ConfiguredStream[] declared =
            [new ConfiguredStream { ReceiverId = ReceiverId, StreamId = StreamId, EventsRequested = [MembershipChanged] }];
        await using var app = await StartAsync(
            beforeMultiTenancy: services =>
            {
                services.AddSingleton<HostCatalog>();
                services.Replace(ServiceDescriptor.Singleton<ITenantCatalog>(
                    provider => provider.GetRequiredService<HostCatalog>()));
            },
            declare: server => server.AddConfiguredStreams("acme", declared));
        Assert.Equal(1, await DispatchAsync(app, "acme", ct));

        var rotated = TenantAt("acme", Acme);
        app.Services.GetRequiredService<HostCatalog>().Own = rotated;

        var token = Assert.Single(await PollAsync(ClientOf(app, Host + Acme), Acme, ct));
        Assert.Equal(rotated.SigningKeys.Single().KeyId, KeyIdOf(token));
    }

    /// <summary>
    /// A push delivery sweep a host sets off from acme's request delivers globex's events as well: each tenant's pass
    /// runs as that tenant.
    /// </summary>
    [Fact]
    public async Task ASweepSetOffFromOneTenantsRequest_DeliversEveryTenantsEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        var receiver = new RecordingReceiver();
        ConfiguredStream[] declared =
        [
            new ConfiguredStream
            {
                ReceiverId = ReceiverId,
                StreamId = StreamId,
                EventsRequested = [MembershipChanged],
                PushEndpointUrl = new Uri(PushEndpoint),
            },
        ];
        await using var app = await StartAsync(
            beforeMultiTenancy: services => services
                .AddHttpClient(nameof(PushDeliverySender))
                .ConfigurePrimaryHttpMessageHandler(() => receiver),
            declare: server => server.AddConfiguredStreams("globex", declared));
        Assert.Equal(1, await DispatchAsync(app, "globex", ct));

        var catalog = app.Services.GetRequiredService<ITenantCatalog>();
        using (TenantScope.Enter((await catalog.FindByIdAsync("acme", ct))!))
            await app.Services.GetRequiredService<IPushDeliverySweep>().SweepAsync(ct);

        Assert.Equal(Host + Globex, IssuerOf(Assert.Single(receiver.Tokens)));
    }

    /// <summary>
    /// The security event tokens the one stream the receiver has at <paramref name="tenant"/> holds, polled from the
    /// address that stream names.
    /// </summary>
    private static async Task<string[]> PollAsync(HttpClient http, string tenant, CancellationToken ct)
    {
        var stream = Assert.Single((await http.GetFromJsonAsync<StreamConfiguration[]>(tenant + StreamPath, ct))!);
        var address = Assert.IsType<Uri>(Assert.IsType<PollDeliveryMethod>(stream.Delivery).EndpointUrl);
        using var polled = await http.PostAsJsonAsync(address, new PollRequest { ReturnImmediately = true }, ct);
        Assert.Equal(HttpStatusCode.OK, polled.StatusCode);
        return [.. (await polled.Content.ReadFromJsonAsync<PollResponse>(ct))!.Sets.Values];
    }

    private static async Task<int> DispatchAsync(WebApplication app, string tenantId, CancellationToken ct)
    {
        var tenant = await app.Services.GetRequiredService<ITenantCatalog>().FindByIdAsync(tenantId, ct);
        using var scope = TenantScope.Enter(tenant!);
        var result = await app.Services.GetRequiredService<EventDispatcher>().DispatchAsync(
            new SecurityEventDescriptor
            {
                EventType = MembershipChanged,
                Subject = new EmailSubject("jdoe@example.com"),
            },
            ct);

        // A stream the event failed on would read as one it was never meant for
        Assert.Empty(result.NotReached);
        return result.Reached;
    }

    private static async Task<JsonNode> KeySetOfAsync(HttpClient http, string tenant, CancellationToken ct)
    {
        var document = await http.GetFromJsonAsync<TransmitterConfiguration>(
            "/.well-known/ssf-configuration" + tenant, ct);
        return (await http.GetFromJsonAsync<JsonNode>(document!.JwksUri, ct))!;
    }

    private static bool VerifiesAgainst(string compactToken, JsonNode keySet)
    {
        var parts = compactToken.Split('.');
        var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64Url.DecodeFromChars(parts[2]);

        return keySet["keys"]!.AsArray()
            .Where(key => key?["kty"]?.GetValue<string>() == "RSA")
            .Any(key =>
            {
                using var rsa = RSA.Create(new RSAParameters
                {
                    Modulus = Base64Url.DecodeFromChars(key!["n"]!.GetValue<string>()),
                    Exponent = Base64Url.DecodeFromChars(key["e"]!.GetValue<string>()),
                });
                return rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            });
    }

    private static string? KeyIdOf(string compactToken)
    {
        var header = Base64Url.DecodeFromChars(compactToken.Split('.')[0]);
        return JsonNode.Parse(header)?[JwtClaimTypes.KeyId]?.GetValue<string>();
    }

    private static string? IssuerOf(string compactToken)
    {
        var payload = Base64Url.DecodeFromChars(compactToken.Split('.')[1]);
        return JsonNode.Parse(payload)?[IanaClaimTypes.Iss]?.GetValue<string>();
    }

    /// <summary>
    /// A client whose requests carry the receiver's credentials as the given issuer issued them.
    /// </summary>
    private static HttpClient ClientOf(WebApplication app, string issuer)
    {
        var http = app.GetTestClient();
        http.BaseAddress = new Uri(Host);
        http.DefaultRequestHeaders.Add(SubjectHeader, ReceiverId);
        http.DefaultRequestHeaders.Add(IssuerHeader, issuer);
        return http;
    }

    private static async Task<WebApplication> StartAsync(
        string issuer = Host,
        Uri? jwksUri = null,
        Action<IServiceCollection>? beforeMultiTenancy = null,
        Action<IServiceCollection>? afterSharedSignals = null,
        Action<IOidcServerBuilder>? declare = null)
    {
        await TestLicense.Loaded;

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddAuthentication().AddCookie();
        builder.Services.AddAuthorization();
        builder.Services.AddConsentGrantedForEveryClient();
        var server = builder.Services.AddOidcServices(options =>
        {
            options.Tenants.Add(TenantAt("acme", Acme));
            options.Tenants.Add(TenantAt("globex", Globex));
        });

        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = issuer,
            JwksUri = jwksUri ?? new Uri(issuer + JwksPath),
            EventsSupported = [MembershipChanged],
            DefaultSubjectsMode = StreamSubjectsMode.All,

            // The test receiver's name resolves nowhere, and the recording handler answers it instead
            AllowedReceiverAddresses = [new Uri(PushEndpoint)],
        });
        beforeMultiTenancy?.Invoke(builder.Services);

        server.AddSharedSignals();
        declare?.Invoke(server);
        afterSharedSignals?.Invoke(builder.Services);

        var app = builder.Build();

        // What a host's bearer authentication leaves behind: the receiver, and the issuer of its credentials
        app.Use((context, next) =>
        {
            if (context.Request.Headers.TryGetValue(SubjectHeader, out var subject))
            {
                Claim[] claims =
                [
                    new(IanaClaimTypes.Sub, subject.ToString()),
                    new(IanaClaimTypes.Iss, context.Request.Headers[IssuerHeader].ToString()),
                ];
                context.User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
            }

            return next(context);
        });
        app.UseMultiTenancy();
        app.UseCors();
        app.UseAuthorization();
        app.MapOidcEndpoints();
        app.MapSharedSignalsTransmitterEndpoints();
        try
        {
            await app.StartAsync(TestContext.Current.CancellationToken);
        }
        catch
        {
            await app.DisposeAsync();
            throw;
        }

        return app;
    }

    private static TenantDefinition TenantAt(string id, string path) => new()
    {
        Id = id,
        Issuer = new Uri(Host + path),
        SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
    };

    /// <summary>
    /// A receiver's push endpoint that keeps every security event token delivered to it and accepts it.
    /// </summary>
    private sealed class RecordingReceiver : HttpMessageHandler
    {
        public List<string> Tokens { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Tokens.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }

    /// <summary>
    /// A catalog of the host's own, which answers with its own definition of a tenant once it holds one and with the
    /// server's otherwise.
    /// </summary>
    private sealed class HostCatalog(StoreTenantCatalog inner) : ITenantCatalog
    {
        public TenantDefinition? Own { get; set; }

        public async ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
            => OwnFor(await inner.FindByIdAsync(tenantId, cancellationToken));

        public async ValueTask<TenantDefinition?> FindByAddressAsync(
            string host,
            string path,
            CancellationToken cancellationToken)
            => OwnFor(await inner.FindByAddressAsync(host, path, cancellationToken));

        private TenantDefinition? OwnFor(TenantDefinition? served)
            => Own is { } own && served is not null && own.Id == served.Id ? own : served;
    }

    /// <summary>
    /// A receiver's push endpoint that holds the delivery of every token one issuer signed until released, and keeps
    /// every other token delivered to it.
    /// </summary>
    private sealed class HoldingReceiver(string heldIssuer) : HttpMessageHandler
    {
        private readonly TaskCompletionSource _held = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ConcurrentQueue<string> Tokens { get; } = [];

        public Task Held => _held.Task;

        public void Release() => _released.TrySetResult();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var token = await request.Content!.ReadAsStringAsync(cancellationToken);
            if (IssuerOf(token) == heldIssuer)
            {
                _held.TrySetResult();
                await _released.Task.WaitAsync(cancellationToken);
            }
            else
            {
                Tokens.Enqueue(token);
            }

            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }
}
