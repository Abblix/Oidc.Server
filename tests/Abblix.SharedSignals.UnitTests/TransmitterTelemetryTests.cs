// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Telemetry;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins what the transmitter records: a span and a count for each security event put into a stream's outbox, and a
/// span, a count and a duration for each token pushed to a receiver, by how the receiver answered.
/// </summary>
public sealed class TransmitterTelemetryTests : IDisposable
{
    private const string Receiver = "https://receiver.example.com";
    private const string StreamId = "s-1";
    private const string EventType = "https://example.com/events/membership-changed";
    private const string Issuer = "https://tr.example.com";

    private readonly ServiceProvider _services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly MeterListener _meterListener = new();
    private readonly ActivityListener _activityListener;
    private readonly ConcurrentQueue<(string Name, object Value, Dictionary<string, object?> Tags)> _measurements = new();
    private readonly ConcurrentQueue<Activity> _spans = new();

    // The spans of this test are the ones under its own trace: tests running beside it record into the same source
    private readonly Activity _trace = new Activity(nameof(TransmitterTelemetryTests)).Start();

    public TransmitterTelemetryTests()
    {
        var meters = _services.GetRequiredService<IMeterFactory>();
        _meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Scope == meters)
                listener.EnableMeasurementEvents(instrument);
        };
        _meterListener.SetMeasurementEventCallback<long>(Record);
        _meterListener.SetMeasurementEventCallback<double>(Record);
        _meterListener.Start();

        _activityListener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SharedSignalsTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = span =>
            {
                if (span.TraceId == _trace.TraceId)
                    _spans.Enqueue(span);
            },
        };
        ActivitySource.AddActivityListener(_activityListener);
    }

    public void Dispose()
    {
        _trace.Dispose();
        _activityListener.Dispose();
        _meterListener.Dispose();
        _services.Dispose();
    }

    private void Record<T>(Instrument instrument, T value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
        where T : struct
        => _measurements.Enqueue((instrument.Name, value, new Dictionary<string, object?>(tags.ToArray())));

    private SharedSignalsInstruments Instruments(string? tenant = null)
        => new(_services.GetRequiredService<IMeterFactory>(), new SwitchableTransmitterIdentity(Issuer) { TenantId = tenant });

    private static StreamState PushStream() => new()
    {
        ReceiverId = "receiver-a",
        Status = StreamStatuses.Enabled,
        SubjectsMode = StreamSubjectsMode.None,
        Configuration = new StreamConfiguration
        {
            StreamId = StreamId,
            Issuer = Issuer,
            Audiences = [Receiver],
            EventsDelivered = [],
            Delivery = new PushDeliveryMethod(new Uri(Receiver + "/events")),
        },
    };

    private static ReceiverAddressPolicy ReachingTheTestReceiver => new(new SharedSignalsTransmitterOptions
    {
        Issuer = Issuer,
        AllowedReceiverAddresses = [new Uri(Receiver)],
    });

    private static async Task<InMemoryEventOutbox> OutboxWithAsync(params OutboxItem[] items)
    {
        var outbox = new InMemoryEventOutbox();
        foreach (var item in items)
            await outbox.EnqueueAsync("receiver-a", StreamId, item, TestContext.Current.CancellationToken);

        return outbox;
    }

    private async Task SendPendingAsync(HttpMessageHandler handler, InMemoryEventOutbox outbox, string? tenant = null)
    {
        var sender = new PushDeliverySender(
            new HttpClient(handler, disposeHandler: false),
            outbox,
            ReachingTheTestReceiver,
            NullLogger<PushDeliverySender>.Instance,
            Instruments(tenant));

        await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);
    }

    private object?[] Outcomes(string instrument)
        => [.. _measurements.Where(m => m.Name == instrument).Select(m => m.Tags[SharedSignalsTags.PushOutcome])];

    [Fact]
    public async Task ATokenTheReceiverAccepts_AndOneItRefuses_AreRecordedAsDeliveredAndRefused()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.Accepted).Enqueue(HttpStatusCode.BadRequest);

        await SendPendingAsync(handler, await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a"), new OutboxItem("jti-2", "b.b.b")));

        object?[] expected = [PushDeliveryOutcomes.Delivered, PushDeliveryOutcomes.Refused];
        Assert.Equal(expected, Outcomes(SharedSignalsMetrics.PushDeliveries));
        Assert.Equal(expected, Outcomes(SharedSignalsMetrics.PushDeliveryDuration));

        var spans = _spans.ToArray();
        Assert.All(spans, span => Assert.Equal(SharedSignalsTelemetry.PushSpan, span.OperationName));
        Assert.Equal(expected, spans.Select(span => span.GetTagItem(SharedSignalsTags.PushOutcome)));
        Assert.Equal([ActivityStatusCode.Unset, ActivityStatusCode.Error], spans.Select(span => span.Status));
    }

    [Fact]
    public async Task AStatusOtherThanSuccessOr400_IsAFailure()
    {
        await SendPendingAsync(
            new StubHttpHandler().Enqueue(HttpStatusCode.ServiceUnavailable),
            await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a")));

        Assert.Equal([PushDeliveryOutcomes.Failed], Outcomes(SharedSignalsMetrics.PushDeliveries));
    }

    /// <summary>
    /// The transport's message names the receiver's address, as the address policy's refusal names the stream, so
    /// the span carries the exception's type alone.
    /// </summary>
    [Fact]
    public async Task ATransportFailure_IsAFailureNamingTheExceptionTypeAlone()
    {
        await SendPendingAsync(
            new ThrowingHandler(new HttpRequestException($"No route to {Receiver}/events for stream {StreamId}")),
            await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a")));

        Assert.Equal([PushDeliveryOutcomes.Failed], Outcomes(SharedSignalsMetrics.PushDeliveries));
        var span = Assert.Single(_spans);
        Assert.Equal(typeof(HttpRequestException).FullName, span.GetTagItem(SharedSignalsTags.ErrorType));
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Null(span.StatusDescription);
        Assert.Empty(span.Events);
        Assert.All(span.TagObjects, tag =>
        {
            Assert.DoesNotContain(Receiver, tag.Value?.ToString() ?? string.Empty);
            Assert.DoesNotContain(StreamId, tag.Value?.ToString() ?? string.Empty);
        });
    }

    [Fact]
    public async Task ATenantTheTransmitterAnswersAs_IsNamedOnTheSpanAndTheMeasurements()
    {
        await SendPendingAsync(
            new StubHttpHandler().Enqueue(HttpStatusCode.Accepted),
            await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a")),
            tenant: "acme");

        Assert.All(_measurements, m => Assert.Equal("acme", m.Tags[SharedSignalsTags.Tenant]));
        Assert.Equal("acme", Assert.Single(_spans).GetTagItem(SharedSignalsTags.Tenant));
    }

    [Fact]
    public async Task WithoutATenant_NoMeasurementNamesOne()
    {
        await SendPendingAsync(
            new StubHttpHandler().Enqueue(HttpStatusCode.Accepted),
            await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a")));

        Assert.NotEmpty(_measurements);
        Assert.All(_measurements, m => Assert.DoesNotContain(SharedSignalsTags.Tenant, m.Tags.Keys));
    }

    [Fact]
    public async Task AnEventPutIntoAStreamsOutbox_IsCountedAndTracedByItsType_ThroughBothDoors()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new InMemoryStreamStore();
        var stream = DispatchedStream("s-1");
        Assert.True(await store.TryCreateAsync(stream, ct));
        var dispatcher = Dispatcher(store, new FixedSigner());

        Assert.Equal(1, await dispatcher.DispatchAsync(Descriptor(), ct));
        await dispatcher.DispatchToStreamAsync(stream, Descriptor(), cancellationToken: ct);

        var transmitted = _measurements.Where(m => m.Name == SharedSignalsMetrics.EventsTransmitted).ToArray();
        Assert.Equal(2, transmitted.Length);
        Assert.All(transmitted, m => Assert.Equal(EventType, m.Tags[SharedSignalsTags.EventType]));
        Assert.Equal(2, _spans.Count(span => span.OperationName == SharedSignalsTelemetry.TransmitSpan
                                             && Equals(span.GetTagItem(SharedSignalsTags.EventType), EventType)));
    }

    [Fact]
    public async Task AnEventThatCouldNotBeSigned_IsNotCounted_AndItsSpanNamesTheFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new InMemoryStreamStore();
        Assert.True(await store.TryCreateAsync(DispatchedStream("s-1"), ct));
        var dispatcher = Dispatcher(store, new FailingSigner());

        Assert.Equal(0, await dispatcher.DispatchAsync(Descriptor(), ct));

        Assert.DoesNotContain(_measurements, m => m.Name == SharedSignalsMetrics.EventsTransmitted);
        var span = Assert.Single(_spans);
        Assert.Equal(typeof(InvalidOperationException).FullName, span.GetTagItem(SharedSignalsTags.ErrorType));
        Assert.Equal(ActivityStatusCode.Error, span.Status);
        Assert.Null(span.StatusDescription);
    }

    private EventDispatcher Dispatcher(IStreamStore store, ISecurityEventTokenSigner signer) => new(
        NullLogger<EventDispatcher>.Instance,
        store,
        new InMemoryEventOutbox(),
        signer,
        new OptionsTransmitterIdentity(new SharedSignalsTransmitterOptions { Issuer = Issuer }),
        Instruments());

    private static StreamState DispatchedStream(string streamId) => new()
    {
        ReceiverId = "receiver-a",
        Status = StreamStatuses.Enabled,
        SubjectsMode = StreamSubjectsMode.All,
        Configuration = new StreamConfiguration
        {
            StreamId = streamId,
            Issuer = Issuer,
            Audiences = [Receiver],
            EventsDelivered = [EventType],
            Delivery = new PollDeliveryMethod(new Uri($"{Issuer}/poll/{streamId}")),
        },
    };

    private static SecurityEventDescriptor Descriptor() => new()
    {
        EventType = EventType,
        Subject = new EmailSubject("jdoe@example.com"),
    };

    private sealed class FixedSigner : ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
            => Task.FromResult("a.b.c");
    }

    private sealed class FailingSigner : ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The key is gone.");
    }

    private sealed class ThrowingHandler(Exception exception) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
            => throw exception;
    }
}
