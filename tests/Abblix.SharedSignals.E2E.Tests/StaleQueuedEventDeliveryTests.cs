// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.MinimalApi;
using Abblix.SecurityEvents.Subjects;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.SharedSignals.Telemetry;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// An event that waited in the outbox longer than the receiver tolerates for a token's issue time - a receiver
/// down for a while, or the queue behind it - still reaches that receiver, which this library also provides.
/// </summary>
/// <remarks>
/// Both hosts read one clock, so the wait is the only difference between this and an event delivered at once:
/// the receiver judges "iat" against the same time the transmitter queued the event and delivered it at.
/// </remarks>
public sealed class StaleQueuedEventDeliveryTests : IAsyncLifetime
{
    private const string TransmitterIssuer = "https://tr.example.com";
    private const string ReceiverId = "receiver-e2e";
    private const string PushEndpoint = "https://receiver.example.com/events";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";

    private readonly FakeTimeProvider _clock = new();
    private readonly JsonWebKey _key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
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
    public async Task AnEventQueuedLongerThanTheIssuedAtTolerance_IsStillDelivered()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var store = _transmitter.Services.GetRequiredService<IStreamStore>();
        var stream = new StreamState
        {
            ReceiverId = ReceiverId,
            Status = StreamStatuses.Enabled,
            SubjectsMode = StreamSubjectsMode.All,
            Configuration = new StreamConfiguration
            {
                StreamId = "s-stale",
                Issuer = TransmitterIssuer,
                Audiences = [ReceiverId],
                EventsDelivered = [MembershipChanged],
                Delivery = new PushDeliveryMethod(new Uri(PushEndpoint)),
            },
        };
        Assert.True(await store.TryCreateAsync(stream, cancellationToken));

        var dispatcher = _transmitter.Services.GetRequiredService<EventDispatcher>();
        Assert.Equal(1, await dispatcher.DispatchAsync(
            new SecurityEventDescriptor { EventType = MembershipChanged, Subject = new EmailSubject("jdoe@example.com") },
            cancellationToken));

        _clock.Advance(new SecurityEventTokenValidationOptions().IssuedAtTolerance + TimeSpan.FromMinutes(1));

        var outcome = await DrainPushAsync(stream, cancellationToken);

        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 1, Rejected: 0), outcome);
        Assert.Single(_sink.Consumed);
    }

    private async Task<PushDeliveryPassOutcome> DrainPushAsync(StreamState stream, CancellationToken cancellationToken)
    {
        var sender = new PushDeliverySender(
            _receiver.GetTestClient(),
            _transmitter.Services.GetRequiredService<IEventOutbox>(),
            _transmitter.Services.GetRequiredService<ReceiverAddressPolicy>(),
            NullLogger<PushDeliverySender>.Instance,
            _transmitter.Services.GetRequiredService<SharedSignalsInstruments>(),
            _transmitter.Services.GetRequiredService<QueuedEventSigner>());

        return await sender.SendPendingAsync(stream, cancellationToken);
    }

    private async Task<WebApplication> StartTransmitterAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<TimeProvider>(_clock);
        builder.Services.AddSecurityEvents(options => options.SigningKeySource = _ => Task.FromResult(_key));
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = TransmitterIssuer,
            EventsSupported = [MembershipChanged],
            PollEndpointFactory = streamId => new Uri($"{TransmitterIssuer}/ssf/poll/{streamId}"),
            AllowedReceiverAddresses = [new Uri(PushEndpoint)],
        });
        builder.Services.AddSingleton(new SharedSignalsEndpointOptions { ReceiverIdSelector = _ => ReceiverId });

        var app = builder.Build();
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private async Task<WebApplication> StartReceiverAsync()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<TimeProvider>(_clock);
        builder.Services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(_key));
        builder.Services.AddSecurityEvents();
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
