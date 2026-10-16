// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text;
using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins how a sweep treats a receiver that asks to be left alone for a while: "Retry-After" on a refusal it means
/// to lift (RFC 9110 Section 10.2.3, RFC 6585 Section 4) holds the stream until then, and a refusal without one
/// leaves the stream to the next sweep.
/// </summary>
public sealed class PushDeliveryRetryAfterTests
{
    private const string ReceiverEndpoint = "https://receiver.example.com/events";

    private static readonly TimeSpan Wait = TimeSpan.FromMinutes(2);

    private readonly FakeTimeProvider _clock = new(DateTimeOffset.FromUnixTimeSeconds(1754040000));
    private readonly ScriptedReceiver _receiver = new();

    private async Task<PushDeliverySweep> SweepWithOneQueuedEventAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var options = new SharedSignalsTransmitterOptions
        {
            Issuer = "https://tr.example.com",
            AllowedReceiverAddresses = [new Uri(ReceiverEndpoint)],
        };
        var store = new InMemoryStreamStore();
        Assert.True(await store.TryCreateAsync(new StreamState
        {
            ReceiverId = "receiver-a",
            Status = StreamStatuses.Enabled,
            SubjectsMode = StreamSubjectsMode.None,
            Configuration = new StreamConfiguration
            {
                StreamId = "s-1",
                Issuer = options.Issuer,
                Audiences = ["https://receiver.example.com"],
                EventsDelivered = [],
                Delivery = new PushDeliveryMethod(new Uri(ReceiverEndpoint)),
            },
        }, ct));

        var outbox = new InMemoryEventOutbox();
        await outbox.EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), ct);

        var sender = new PushDeliverySender(
            new HttpClient(_receiver, disposeHandler: false),
            outbox,
            new ReceiverAddressPolicy(options),
            NullLogger<PushDeliverySender>.Instance,
            TestInstruments.Create(),
            TestQueuedEventSigner.Create(_clock));

        return new PushDeliverySweep(
            NullLogger<PushDeliverySweep>.Instance,
            store,
            sender,
            new ProcessLocalDeliveryLease(_clock),
            options,
            _clock);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task ARetryAfterInSeconds_HoldsTheStreamUntilItPasses(HttpStatusCode status)
    {
        var sweep = await SweepWithOneQueuedEventAsync();
        _receiver.Answer(status, retryAfter: new RetryConditionHeaderValue(Wait));

        await sweep.SweepAsync(TestContext.Current.CancellationToken);
        await sweep.SweepAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, _receiver.Requests);

        _clock.Advance(Wait);
        _receiver.Answer(HttpStatusCode.Accepted);
        await sweep.SweepAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, _receiver.Requests);
    }

    [Fact]
    public async Task ARetryAfterAsADate_HoldsTheStreamUntilThatMoment()
    {
        var sweep = await SweepWithOneQueuedEventAsync();
        _receiver.Answer(
            HttpStatusCode.ServiceUnavailable,
            retryAfter: new RetryConditionHeaderValue(_clock.GetUtcNow() + Wait));

        await sweep.SweepAsync(TestContext.Current.CancellationToken);
        _clock.Advance(Wait - TimeSpan.FromSeconds(1));
        await sweep.SweepAsync(TestContext.Current.CancellationToken);
        Assert.Equal(1, _receiver.Requests);

        _clock.Advance(TimeSpan.FromSeconds(1));
        _receiver.Answer(HttpStatusCode.Accepted);
        await sweep.SweepAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, _receiver.Requests);
    }

    /// <summary>
    /// A 400 objecting to the transmitter rather than to the event keeps the event queued, so a wait it names holds
    /// the stream as a 429 does.
    /// </summary>
    [Fact]
    public async Task AnObjectionWithRetryAfter_HoldsTheStreamToo()
    {
        var sweep = await SweepWithOneQueuedEventAsync();
        _receiver.Answer(
            HttpStatusCode.BadRequest,
            retryAfter: new RetryConditionHeaderValue(Wait),
            json: $$"""{"err": "{{DeliveryErrorCodes.AccessDenied}}", "description": "-"}""");

        await sweep.SweepAsync(TestContext.Current.CancellationToken);
        await sweep.SweepAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, _receiver.Requests);
    }

    [Fact]
    public async Task ARefusalWithoutRetryAfter_LeavesTheStreamToTheNextSweep()
    {
        var sweep = await SweepWithOneQueuedEventAsync();
        _receiver.Answer(HttpStatusCode.ServiceUnavailable);
        await sweep.SweepAsync(TestContext.Current.CancellationToken);

        _receiver.Answer(HttpStatusCode.Accepted);
        await sweep.SweepAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, _receiver.Requests);
    }

    /// <summary>
    /// The wait is the receiver's to name, so it is bounded here: a receiver answering with a wait of a week would
    /// otherwise hold its events for that week after it came back.
    /// </summary>
    [Fact]
    public async Task ARetryAfterBeyondTheCeiling_HoldsTheStreamOnlyForTheCeiling()
    {
        var sweep = await SweepWithOneQueuedEventAsync();
        _receiver.Answer(
            HttpStatusCode.TooManyRequests,
            retryAfter: new RetryConditionHeaderValue(PushDeliverySweep.RetryAfterCeiling + Wait));
        await sweep.SweepAsync(TestContext.Current.CancellationToken);

        _clock.Advance(PushDeliverySweep.RetryAfterCeiling);
        _receiver.Answer(HttpStatusCode.Accepted);
        await sweep.SweepAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, _receiver.Requests);
    }

    /// <summary>A receiver answering each request with the next scripted status and "Retry-After".</summary>
    private sealed class ScriptedReceiver : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode Status, RetryConditionHeaderValue? RetryAfter, string? Json)> _answers =
            new();

        public int Requests { get; private set; }

        public void Answer(HttpStatusCode status, RetryConditionHeaderValue? retryAfter = null, string? json = null)
            => _answers.Enqueue((status, retryAfter, json));

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            var (status, retryAfter, json) = _answers.Dequeue();
            var response = new HttpResponseMessage(status);
            response.Headers.RetryAfter = retryAfter;
            if (json is not null)
            {
                response.Content = new StringContent(json, Encoding.UTF8, MediaTypeNames.Application.Json);
            }

            return Task.FromResult(response);
        }
    }
}
