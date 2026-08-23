// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Mime;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Abblix.SecurityEvents.Delivery;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the transmitter's delivery halves: the push pass (RFC 8935 - order, acknowledgement on
/// 202, terminal drop on 400, stop on transient failure) and the poll exchange (RFC 8936 -
/// release on ack and on error report, the ack-only poll, pagination), plus the one rule both
/// share: a stream that is not enabled carries nothing except status announcements.
/// </summary>
public class TransmitterDeliveryTests
{
    private static StreamState PushStream(string status = StreamStatuses.Enabled) => new()
    {
        ReceiverId = "receiver-a",
        Status = status,
        SubjectsMode = StreamSubjectsMode.None,
        Configuration = new StreamConfiguration
        {
            StreamId = "s-1",
            Issuer = "https://tr.example.com",
            Audiences = ["https://receiver.example.com"],
            EventsDelivered = [],
            Delivery = new PushDeliveryMethod(new Uri("https://receiver.example.com/events"))
            {
                AuthorizationHeader = "Bearer push-secret",
            },
        },
    };

    /// <summary>
    /// Permits the receiver these tests deliver to, so the address policy is not what they are measuring.
    /// </summary>
    /// <remarks>
    /// Named as an operator permission rather than a relaxation: without it the policy would resolve
    /// "receiver.example.com" over the network, which is neither this suite's subject nor its business.
    /// The policy's own rules are covered in <see cref="ReceiverAddressPolicyTests"/>.
    /// </remarks>
    private static ReceiverAddressPolicy ReachingTheTestReceiver => new(new SharedSignalsTransmitterOptions
    {
        Issuer = "https://tr.example.com",
        AllowedReceiverAddresses = [new Uri("https://receiver.example.com")],
    });

    private static async Task<InMemoryEventOutbox> OutboxWithAsync(params OutboxItem[] items)
    {
        var outbox = new InMemoryEventOutbox();
        foreach (var item in items)
        {
            await outbox.EnqueueAsync("s-1", item, TestContext.Current.CancellationToken);
        }

        return outbox;
    }

    [Fact]
    public async Task Push_DeliversInOrder_WithTheMediaTypeAndTheReceiversAuthorization()
    {
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.Accepted)
            .Enqueue(HttpStatusCode.Accepted);
        var outbox = await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a"), new OutboxItem("jti-2", "b.b.b"));
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, NullLogger<PushDeliverySender>.Instance);

        var outcome = await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 2, Rejected: 0), outcome);
        Assert.Empty(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.Equal(["a.a.a", "b.b.b"], handler.Requests.Select(request => request.Body));
    }

    [Fact]
    public async Task Push_BadRequest_IsTerminal_AndTransientFailureStopsThePass()
    {
        // The 400 is the receiver's judgment of THAT SET - retrying the same bytes cannot
        // succeed, so it is dropped and the pass continues; the 503 is the world's weather, so
        // the pass stops and the rest waits in order for the next one.
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.BadRequest, """{"err": "invalid_audience", "description": "-"}""")
            .Enqueue(HttpStatusCode.ServiceUnavailable);
        var outbox = await OutboxWithAsync(
            new OutboxItem("jti-1", "a.a.a"),
            new OutboxItem("jti-2", "b.b.b"),
            new OutboxItem("jti-3", "c.c.c"));
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, NullLogger<PushDeliverySender>.Instance);

        var outcome = await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 0, Rejected: 1), outcome);
        Assert.Equal(
            ["jti-2", "jti-3"],
            (await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken))
            .Select(item => item.JwtId));
    }

    /// <summary>The receiver's own reason for refusing a SET reaches this deployment's log.</summary>
    /// <remarks>
    /// <para>
    /// RFC 8935 Section 2.3 makes the receiver owe an error body with a 400, and it arrives here - it was
    /// already read to decide whether the refusal is final. Dropping it after that decision left this side
    /// holding a status code, and the receiver's own log is not ours to read, so a stream refusing every SET
    /// looked from here exactly like a stream refusing none.
    /// </para>
    /// <para>
    /// Both halves are asserted, because a code without a description names a class of problem and a
    /// description without a code cannot be grouped.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Push_BadRequest_CarriesTheReceiversReasonIntoTheLog()
    {
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.BadRequest,
            """{"err": "invalid_audience", "description": "aud names a receiver this stream is not"}""");
        var outbox = await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a"));
        var logger = new CapturingLogger();

        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, logger);
        await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        var written = Assert.Single(logger.Written);
        Assert.Contains("invalid_audience", written, StringComparison.Ordinal);
        Assert.Contains("aud names a receiver this stream is not", written, StringComparison.Ordinal);

        // The SET is named too: a deployment with several queued events needs to know WHICH one was refused.
        Assert.Contains("jti-1", written, StringComparison.Ordinal);
    }

    /// <summary>The control: a delivery the receiver accepts writes nothing.</summary>
    /// <remarks>
    /// Without it the assertion above is satisfied by a sender that logs on every pass, which would bury the
    /// refusals it exists to surface - the shape this whole line of work started from.
    /// </remarks>
    [Fact]
    public async Task Push_Accepted_WritesNothing()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.Accepted);
        var outbox = await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a"));
        var logger = new CapturingLogger();

        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, logger);
        await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        Assert.Empty(logger.Written);
    }

    /// <summary>Keeps what was written, formatted the way a log sink would render it.</summary>
    private sealed class CapturingLogger : ILogger<PushDeliverySender>
    {
        public List<string> Written { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Written.Add(formatter(state, exception));

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();
            public void Dispose() { }
        }
    }

    /// <summary>
    /// A 400 about the transmitter rather than about the event keeps the event queued: RFC 8935 Section 4 names
    /// exactly this case as one a retransmission can succeed at, "if the SET Transmitter refreshes expired
    /// credentials prior to retransmission".
    /// </summary>
    [Theory]
    [InlineData(DeliveryErrorCodes.AuthenticationFailed)]
    [InlineData(DeliveryErrorCodes.AccessDenied)]
    public async Task Push_BadRequestAboutTheTransmitter_KeepsTheEventQueued(string errorCode)
    {
        var handler = new StubHttpHandler()
            .Enqueue(HttpStatusCode.BadRequest, $$"""{"err": "{{errorCode}}", "description": "-"}""");
        var outbox = await OutboxWithAsync(
            new OutboxItem("jti-1", "a.a.a"),
            new OutboxItem("jti-2", "b.b.b"));
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, NullLogger<PushDeliverySender>.Instance);

        var outcome = await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        // Nothing delivered, nothing dropped, and the pass stopped rather than spending the queue on a receiver
        // that is refusing this transmitter for a reason a deployment can fix.
        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 0, Rejected: 0), outcome);
        Assert.Equal(
            ["jti-1", "jti-2"],
            (await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken))
            .Select(item => item.JwtId));
    }

    /// <summary>
    /// A 400 whose body cannot be read as a verdict is treated as final, because the alternative lets a receiver
    /// answering with an error page hold the head of the queue indefinitely.
    /// </summary>
    [Theory]
    [InlineData("not json at all", MediaTypeNames.Text.Html)]
    [InlineData("""{"err": "something_the_registry_does_not_have", "description": "-"}""",
        MediaTypeNames.Application.Json)]
    public async Task Push_BadRequestWithoutAReadableVerdict_DropsTheEvent(string body, string mediaType)
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.BadRequest, body, mediaType);
        var outbox = await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a"));
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, NullLogger<PushDeliverySender>.Instance);

        var outcome = await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 0, Rejected: 1), outcome);
        Assert.Empty(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Push_PausedStream_CarriesOnlyTheStatusAnnouncement()
    {
        // Holding is the pause's meaning (SSF 1.0 Section 8.1.2.1); the announcement is what
        // Section 8.1.5 still owes the receiver after the stop.
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.Accepted);
        var outbox = await OutboxWithAsync(
            new OutboxItem("jti-1", "a.a.a"),
            new OutboxItem("jti-2", "b.b.b", IsStatusAnnouncement: true));
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, NullLogger<PushDeliverySender>.Instance);

        var outcome = await sender.SendPendingAsync(
            PushStream(StreamStatuses.Paused), TestContext.Current.CancellationToken);

        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 1, Rejected: 0), outcome);
        Assert.Equal("b.b.b", Assert.Single(handler.Requests).Body);
        var held = Assert.Single(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.Equal("jti-1", held.JwtId);
    }

    [Fact]
    public async Task Poll_ReleasesAcknowledgedAndErrored_AndPages()
    {
        var outbox = await OutboxWithAsync(
            new OutboxItem("jti-1", "a.a.a"),
            new OutboxItem("jti-2", "b.b.b"),
            new OutboxItem("jti-3", "c.c.c"));
        var handler = new PollEndpointHandler(outbox);

        var response = await handler.HandleAsync(
            PushStream(),
            new PollRequest
            {
                Acknowledged = ["jti-1"],
                Errors = new Dictionary<string, DeliveryError>
                {
                    ["jti-2"] = new(DeliveryErrorCodes.InvalidRequest, "unreadable"),
                },
                MaxEvents = 5,
            },
            TestContext.Current.CancellationToken);

        // Both the acknowledgement and the error report release retention (RFC 8936
        // Section 2.2): only the third SET remains, and it is what the response carries.
        Assert.Equal(["jti-3"], response.Sets.Keys);
        Assert.Null(response.MoreAvailable);
    }

    [Fact]
    public async Task Poll_AckOnly_AnswersTheEmptySetsObject_AndPaginationSignalsMore()
    {
        var outbox = await OutboxWithAsync(
            new OutboxItem("jti-1", "a.a.a"),
            new OutboxItem("jti-2", "b.b.b"));
        var handler = new PollEndpointHandler(outbox);

        var ackOnly = await handler.HandleAsync(
            PushStream(), new PollRequest { MaxEvents = 0 }, TestContext.Current.CancellationToken);
        Assert.Empty(ackOnly.Sets);
        Assert.Null(ackOnly.MoreAvailable);

        var page = await handler.HandleAsync(
            PushStream(), new PollRequest { MaxEvents = 1 }, TestContext.Current.CancellationToken);
        Assert.Equal(["jti-1"], page.Sets.Keys);
        Assert.True(page.MoreAvailable);
    }

    [Fact]
    public async Task Poll_PausedStream_ServesOnlyTheStatusAnnouncement()
    {
        var outbox = await OutboxWithAsync(
            new OutboxItem("jti-1", "a.a.a"),
            new OutboxItem("jti-2", "b.b.b", IsStatusAnnouncement: true));
        var handler = new PollEndpointHandler(outbox);

        var response = await handler.HandleAsync(
            PushStream(StreamStatuses.Paused), new PollRequest(), TestContext.Current.CancellationToken);

        Assert.Equal(["jti-2"], response.Sets.Keys);
        Assert.Null(response.MoreAvailable);
    }

    [Fact]
    public async Task TransmitterInitiatedDisable_DropsTheQueue_ButTheAnnouncementSurvives()
    {
        // The Section 8.1.5 orchestration end to end: held events die with the disable, the
        // stream-updated announcement is enqueued after the drop and marked to travel over the
        // stopped stream.
        var store = new InMemoryStreamStore();
        var stream = PushStream();
        Assert.True(await store.TryCreateAsync(stream, TestContext.Current.CancellationToken));

        var outbox = await OutboxWithAsync(new OutboxItem("jti-held", "h.h.h"));
        var signer = new FakeSigner();
        var options = new SharedSignalsTransmitterOptions { Issuer = "https://tr.example.com" };
        var dispatcher = new EventDispatcher(
            NullLogger<EventDispatcher>.Instance, store, outbox, signer, options.Issuer);
        var service = new StreamManagementService(store, outbox, dispatcher, options, PolicyFor(options));

        Assert.True(await service.ChangeStreamStatusAsync(
            "receiver-a", "s-1", StreamStatuses.Disabled, "maintenance",
            TestContext.Current.CancellationToken));

        var remaining = Assert.Single(
            await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.True(remaining.IsStatusAnnouncement);
        Assert.NotEqual("jti-held", remaining.JwtId);
        Assert.Equal(
            StreamStatuses.Disabled,
            (await store.FindAsync("receiver-a", "s-1", TestContext.Current.CancellationToken))!.Status);
    }

    private sealed class FakeSigner : Abblix.SecurityEvents.Abstractions.ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(
            Abblix.SecurityEvents.SecurityEventToken token,
            CancellationToken cancellationToken = default)
            => Task.FromResult($"signed.{token.JwtId}");
    }

    /// <summary>
    /// The address policy these tests hand to the service, with a resolver of their own: the one branch
    /// of the policy that is not a string comparison would otherwise reach a live DNS for a name nobody
    /// owns, and the test would measure the network.
    /// </summary>
    private static ReceiverAddressPolicy PolicyFor(SharedSignalsTransmitterOptions options)
        => new(options, (_, _) => Task.FromResult<System.Net.IPAddress[]>(
            [System.Net.IPAddress.Parse("93.184.216.34")]));
}
