// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.MinimalApi;
using Abblix.SecurityEvents.Subjects;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Events;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// The whole framework as two real hosts talking HTTP: a transmitter serving discovery, the
/// management API and poll delivery through the Minimal API adapter, and a receiver whose push
/// intake runs the composed validation pipeline over a genuine RS256 signature. Every hop is
/// the shipped code path - the receiver's clients, the transmitter's endpoints, the delivery
/// senders - so a green run means the packages carry both roles end to end.
/// </summary>
public sealed class SharedSignalsEndToEndTests : IAsyncLifetime
{
    private const string TransmitterIssuer = "https://tr.example.com";
    private const string ReceiverId = "receiver-e2e";
    private const string PushEndpoint = "https://receiver.example.com/events";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";

    private readonly JsonWebKey _key =
        JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

    private readonly RecordingSink _sink = new();

    private WebApplication _transmitter = null!;
    private WebApplication _receiver = null!;

    public async ValueTask InitializeAsync()
    {
        _transmitter = await StartTransmitterAsync();
        _receiver = await StartReceiverAsync();
    }

    public async ValueTask DisposeAsync()
    {
        await _receiver.DisposeAsync();
        await _transmitter.DisposeAsync();
    }

    [Fact]
    public async Task DiscoveryToPushDelivery_CarriesAVerifiedEvent_AndARedeliveryIsAcknowledged()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var management = await DiscoverAndCreatePushStreamAsync(cancellationToken);
        var stream = management.Created;

        // The receiver names its subject and asks the stream to prove itself.
        Assert.True(await management.Client.AddSubjectAsync(
            new AddSubjectRequest { StreamId = stream.StreamId, Subject = Jdoe() },
            cancellationToken));
        Assert.True(await management.Client.RequestVerificationAsync(
            new VerificationRequest { StreamId = stream.StreamId, State = "e2e-state" },
            cancellationToken));

        // The transmitter drains its outbox into the receiver's real push endpoint.
        Assert.Equal(1, (await DrainPushAsync(stream.StreamId, cancellationToken)).Delivered);

        var verification = Assert.Single(_sink.Consumed);
        Assert.Equal(
            stream.StreamId,
            Assert.IsType<OpaqueSubject>(verification.Token.GetSubjectId()).Id);
        Assert.Equal(
            "e2e-state",
            Assert.IsType<VerificationEventPayload>(
                verification.EventPayloads![SharedSignalsEventTypes.Verification]).State);

        // A business event reaches the stream through the matching fan-out.
        var dispatcher = _transmitter.Services.GetRequiredService<EventDispatcher>();
        Assert.Equal(1, await dispatcher.DispatchAsync(
            new SecurityEventDescriptor { EventType = MembershipChanged, Subject = Jdoe() },
            cancellationToken));

        // Captured before draining, so the exact same SET can be redelivered afterwards.
        var outbox = _transmitter.Services.GetRequiredService<IEventOutbox>();
        var minted = Assert.Single(
            await outbox.PendingAsync(stream.StreamId, null, cancellationToken));

        Assert.Equal(1, (await DrainPushAsync(stream.StreamId, cancellationToken)).Delivered);
        Assert.Equal(2, _sink.Consumed.Count);

        // RFC 8935 Section 2 lets the transmitter redeliver regardless of earlier responses, and
        // asks the receiver to answer as though it had not seen the token before: the repeat earns
        // the same 202 and reaches the sink again, whose contract is idempotency. Short-circuiting
        // it here is what used to swallow a delivery the sink had refused.
        await outbox.EnqueueAsync(stream.StreamId, minted, cancellationToken);
        Assert.Equal(1, (await DrainPushAsync(stream.StreamId, cancellationToken)).Delivered);
        Assert.Equal(3, _sink.Consumed.Count);
    }

    [Fact]
    public async Task PollLifecycle_SwitchesDelivery_HoldsAcrossAPause_AndEndsWithDeletion()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var management = await DiscoverAndCreatePushStreamAsync(cancellationToken);
        var streamId = management.Created.StreamId;
        var client = management.Client;

        Assert.True(await client.AddSubjectAsync(
            new AddSubjectRequest { StreamId = streamId, Subject = Jdoe() }, cancellationToken));

        // The receiver proposes poll with the bare method - the endpoint URL is the
        // transmitter's to supply, and the update answers with it.
        var updated = await client.UpdateAsync(
            new UpdateStreamRequest { StreamId = streamId, Delivery = new PollDeliveryMethod() },
            cancellationToken);
        var poll = Assert.IsType<PollDeliveryMethod>(updated!.Delivery);
        Assert.NotNull(poll.EndpointUrl);

        var dispatcher = _transmitter.Services.GetRequiredService<EventDispatcher>();
        var pollClient = new PollClient(_transmitter.GetTestClient());

        Assert.Equal(1, await dispatcher.DispatchAsync(
            new SecurityEventDescriptor { EventType = MembershipChanged, Subject = Jdoe() },
            cancellationToken));

        var page = await pollClient.PollAsync(poll, new PollRequest(), cancellationToken);
        var jwtId = Assert.Single(page.Sets).Key;

        // Acknowledging releases retention; the next poll is empty.
        var afterAcknowledge = await pollClient.PollAsync(
            poll, new PollRequest { Acknowledged = [jwtId] }, cancellationToken);
        Assert.Empty(afterAcknowledge.Sets);

        // Paused holds: the event waits invisible until the receiver enables the stream again.
        await client.UpdateStatusAsync(
            new StreamStatus { StreamId = streamId, Status = StreamStatuses.Paused },
            cancellationToken);
        Assert.Equal(1, await dispatcher.DispatchAsync(
            new SecurityEventDescriptor { EventType = MembershipChanged, Subject = Jdoe() },
            cancellationToken));
        Assert.Empty((await pollClient.PollAsync(poll, new PollRequest(), cancellationToken)).Sets);

        await client.UpdateStatusAsync(
            new StreamStatus { StreamId = streamId, Status = StreamStatuses.Enabled },
            cancellationToken);
        Assert.Single((await pollClient.PollAsync(poll, new PollRequest(), cancellationToken)).Sets);

        // Deletion ends the stream; reading it back answers nothing.
        await client.DeleteAsync(streamId, cancellationToken);
        Assert.Null(await client.GetAsync(streamId, cancellationToken));
    }

    [Fact]
    public async Task ManagementSurface_ReplacesTheStream_ReadsItsStatus_AndSubjectRemovalStopsMatching()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var management = await DiscoverAndCreatePushStreamAsync(cancellationToken);
        var streamId = management.Created.StreamId;
        var client = management.Client;

        // The status read (SSF 1.0 Section 8.1.2.1): a fresh stream answers enabled, an unknown
        // stream answers nothing rather than someone else's status.
        var status = await client.GetStatusAsync(streamId, cancellationToken);
        Assert.Equal(StreamStatuses.Enabled, status!.Status);
        Assert.Null(await client.GetStatusAsync("no-such-stream", cancellationToken));

        Assert.True(await client.AddSubjectAsync(
            new AddSubjectRequest { StreamId = streamId, Subject = Jdoe() }, cancellationToken));

        // The PUT replacement (SSF 1.0 Section 8.1.1.4) carries the full receiver-supplied set,
        // and the answer is the whole configuration with the transmitter's delivery answer in it.
        var replaced = await client.ReplaceAsync(
            new UpdateStreamRequest
            {
                StreamId = streamId,
                EventsRequested = [MembershipChanged],
                Delivery = new PollDeliveryMethod(),
            },
            cancellationToken);
        Assert.NotNull(Assert.IsType<PollDeliveryMethod>(replaced!.Delivery).EndpointUrl);
        Assert.Equal([MembershipChanged], replaced.EventsDelivered);

        // The subject survived the replacement: the event still fans out to this stream.
        var dispatcher = _transmitter.Services.GetRequiredService<EventDispatcher>();
        Assert.Equal(1, await dispatcher.DispatchAsync(
            new SecurityEventDescriptor { EventType = MembershipChanged, Subject = Jdoe() },
            cancellationToken));

        // Removal's CONSEQUENCE, not its status code: the same event now matches no stream.
        Assert.True(await client.RemoveSubjectAsync(
            new RemoveSubjectRequest { StreamId = streamId, Subject = Jdoe() }, cancellationToken));
        Assert.Equal(0, await dispatcher.DispatchAsync(
            new SecurityEventDescriptor { EventType = MembershipChanged, Subject = Jdoe() },
            cancellationToken));
    }

    [Fact]
    public async Task GatewayFrontedTransmitter_SuppressesWellKnown_AndServesTheDocumentOnItsOwnRoute()
    {
        // The deployment behind a rewriting proxy: the canonical well-known address is answered
        // by the gateway, the application serves the same document on an internal route, and the
        // document advertises the EXTERNAL prefix the proxy exposes.
        var cancellationToken = TestContext.Current.CancellationToken;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSecurityEvents(options =>
            options.SigningKeySource = _ => Task.FromResult(_key));
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = TransmitterIssuer,
            EventsSupported = [MembershipChanged],
        });
        // The whole topology in one options object: internal routes, the external prefix the
        // proxy exposes, and the suppressed canonical address the gateway owns.
        builder.Services.AddSingleton(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = _ => ReceiverId,
            MapWellKnownConfiguration = false,
            ManagementPrefix = "/internal/ssf",
            AdvertisedPrefix = "/api/ssf",
            ConfigurationDocumentRoute = "/internal/ssf-config",
        });

        await using var app = builder.Build();
        app.MapSharedSignalsTransmitterEndpoints();
        app.MapSharedSignalsConfigurationDocument();
        await app.StartAsync(cancellationToken);

        var http = app.GetTestClient();

        // The canonical address is deliberately silent here - the gateway in front owns it.
        using var wellKnown = await http.GetAsync("/.well-known/ssf-configuration", cancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, wellKnown.StatusCode);

        // The receiver's client reads the internal route through its explicit-address overload,
        // and the identity check still binds the document to the issuer.
        var metadata = await new TransmitterConfigurationClient(http).GetAsync(
            new Uri(TransmitterIssuer),
            new Uri($"{TransmitterIssuer}/internal/ssf-config"),
            cancellationToken);

        Assert.Equal(TransmitterIssuer, metadata.Issuer);
        Assert.StartsWith(
            $"{TransmitterIssuer}/api/ssf/",
            metadata.ConfigurationEndpoint!.AbsoluteUri);

        // The management surface itself answers where it was actually mapped.
        using var streams = await http.GetAsync("/internal/ssf/stream", cancellationToken);
        Assert.Equal(HttpStatusCode.OK, streams.StatusCode);
    }

    private sealed record ManagementSurface(StreamManagementClient Client, StreamConfiguration Created);

    /// <summary>
    /// The receiver's opening moves, through its own shipped clients: discover the transmitter
    /// at the well-known address, confirm its identity, and create a push stream - proving on
    /// the way that a second create answers 409.
    /// </summary>
    private async Task<ManagementSurface> DiscoverAndCreatePushStreamAsync(
        CancellationToken cancellationToken)
    {
        var transmitterClient = _transmitter.GetTestClient();

        var metadata = await new TransmitterConfigurationClient(transmitterClient)
            .GetAsync(new Uri(TransmitterIssuer), cancellationToken);
        Assert.Equal(TransmitterIssuer, metadata.Issuer);

        var client = new StreamManagementClient(transmitterClient, metadata);
        var created = await client.CreateAsync(
            new CreateStreamRequest
            {
                EventsRequested = [MembershipChanged],
                Delivery = new PushDeliveryMethod(new Uri(PushEndpoint)),
            },
            cancellationToken);

        Assert.NotNull(created);
        Assert.Equal([MembershipChanged], created.EventsDelivered);
        Assert.Null(await client.CreateAsync(new CreateStreamRequest(), cancellationToken));

        return new ManagementSurface(client, created);
    }

    private async Task<PushDeliveryPassOutcome> DrainPushAsync(
        string streamId,
        CancellationToken cancellationToken)
    {
        var store = _transmitter.Services.GetRequiredService<IStreamStore>();
        var stream = await store.FindAsync(ReceiverId, streamId, cancellationToken);

        var sender = new PushDeliverySender(
            _receiver.GetTestClient(),
            _transmitter.Services.GetRequiredService<IEventOutbox>(),
            _transmitter.Services.GetRequiredService<ReceiverAddressPolicy>(), NullLogger<PushDeliverySender>.Instance);

        return await sender.SendPendingAsync(stream!, cancellationToken);
    }

    private async Task<WebApplication> StartTransmitterAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSecurityEvents(options =>
            options.SigningKeySource = _ => Task.FromResult(_key));
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = TransmitterIssuer,
            EventsSupported = [MembershipChanged],
            PollEndpointFactory = streamId => new Uri($"{TransmitterIssuer}/ssf/poll/{streamId}"),

            // The receiver in this suite is a test server rather than a host on the network, so the address
            // policy is told about it the way an operator tells it about a receiver of its own.
            AllowedReceiverAddresses = [new Uri(PushEndpoint)],
        });

        // The test host's stand-in for authentication: every request is the one receiver. A
        // real deployment authenticates and attaches authorization to the returned group.
        builder.Services.AddSingleton(new SharedSignalsEndpointOptions
        {
            ReceiverIdSelector = _ => ReceiverId,
        });

        var app = builder.Build();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private async Task<WebApplication> StartReceiverAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(_key));
        builder.Services.AddSecurityEvents(options =>
            options.Events.Register<VerificationEventPayload>(SharedSignalsEventTypes.Verification));
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddDistributedReplayCache();
        builder.Services.AddSharedSignalsReceiver(new SharedSignalsValidationOptions
        {
            ExpectedAudience = ReceiverId,
            ExpectedIssuers = [TransmitterIssuer],
            StreamIssuer = TransmitterIssuer,
        });
        builder.Services.AddSingleton<ISecurityEventSink>(_sink);

        var app = builder.Build();
        app.MapPushDeliveryEndpoint("/events");
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static EmailSubject Jdoe() => new("jdoe@example.com");

    private sealed class RecordingSink : ISecurityEventSink
    {
        public List<ValidatedSecurityEventToken> Consumed { get; } = [];

        public Task<DeliveryError?> ConsumeAsync(
            ValidatedSecurityEventToken token,
            CancellationToken cancellationToken = default)
        {
            Consumed.Add(token);
            return Task.FromResult<DeliveryError?>(null);
        }
    }

    private sealed class FixedKeyResolver(params JsonWebKey[] keys) : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            foreach (var key in keys)
            {
                yield return key;
            }
        }
    }
}
