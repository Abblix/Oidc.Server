// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Mime;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals;
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

    /// <summary>The receiver's own reason for refusing SETs reaches this deployment's log, once for the pass.</summary>
    /// <remarks>
    /// <para>
    /// RFC 8935 Section 2.3 makes the receiver owe an error body with a 400, and it is read here to decide
    /// whether a retransmission could ever succeed. Nothing else carries it onward: this side holds a status
    /// code, the receiver's log is not ours to read, and a stream refusing everything is indistinguishable
    /// from one refusing nothing.
    /// </para>
    /// <para>
    /// Three queued events and ONE line, because the queue is read whole: a line per SET would write
    /// thousands in a pass for a receiver refusing a backlog, differing only in an identifier. The count
    /// carries what the repetition would have.
    /// </para>
    /// <para>
    /// The level and the event id are asserted because they are what a log pipeline filters on. A level
    /// below the host's floor makes the line invisible and an id nobody publishes makes a runbook miss it,
    /// and the rendered text is identical in both cases.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Push_BadRequest_CarriesTheReceiversReasonIntoTheLog_OncePerPass()
    {
        var handler = new StubHttpHandler();
        for (var i = 0; i < 3; i++)
        {
            handler.Enqueue(
                HttpStatusCode.BadRequest,
                """{"err": "invalid_audience", "description": "aud names a receiver this stream is not"}""");
        }

        var outbox = await OutboxWithAsync(
            new OutboxItem("jti-1", "a.a.a"), new OutboxItem("jti-2", "b.b.b"), new OutboxItem("jti-3", "c.c.c"));
        var logger = new CapturingLogger();

        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, logger);
        var outcome = await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        Assert.Equal(3, outcome.Rejected);

        var written = Assert.Single(logger.Written);
        Assert.Equal(LogLevel.Warning, written.Level);
        Assert.Equal(LogEvents.Transmitter.SetsRefusedByReceiver, written.Event.Id);
        Assert.Contains("invalid_audience", written.Text, StringComparison.Ordinal);
        Assert.Contains("aud names a receiver this stream is not", written.Text, StringComparison.Ordinal);

        // The count and the stream are asserted where they belong in the sentence: a pair swapped at the
        // call site renders a plausible line and compiles, because both sides are what the template expects.
        Assert.Contains("refused 3 SET(s)", written.Text, StringComparison.Ordinal);
        Assert.Contains("on stream s-1", written.Text, StringComparison.Ordinal);
    }

    /// <summary>An objection to the transmitter is its own event, and it holds the queue.</summary>
    /// <remarks>
    /// The queue disposition is what an operator acts on, and it is the opposite of the case above: nothing
    /// is lost, and the events go out once the credential or the grant is put right. Told apart by event id
    /// rather than by reading the sentence, because that is what a runbook keys on.
    /// </remarks>
    [Fact]
    public async Task Push_BadRequestAboutTheTransmitter_SaysSoAndHoldsTheQueue()
    {
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.BadRequest,
            $$"""{"err": "{{DeliveryErrorCodes.AccessDenied}}", "description": "no grant for this stream"}""");
        var outbox = await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a"));
        var logger = new CapturingLogger();

        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, logger);
        await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        var written = Assert.Single(logger.Written);
        Assert.Equal(LogLevel.Warning, written.Level);
        Assert.Equal(LogEvents.Transmitter.ReceiverObjected, written.Event.Id);
        Assert.Contains("no grant for this stream", written.Text, StringComparison.Ordinal);

        // The event is still owed to the receiver, so it stays queued.
        Assert.Single(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
    }

    /// <summary>The receiver's words are bounded and cannot forge a line of their own.</summary>
    /// <remarks>
    /// The field is the receiver's to fill and RFC 8935 Section 2.3 puts no bound on it, so it arrives as
    /// text of any length from a party this deployment does not control. A plain-text sink writes a newline
    /// as a newline, which is a whole fabricated entry in somebody else's gift.
    /// </remarks>
    [Fact]
    public async Task Push_BadRequest_NeitherLetsTheReceiverWriteALineNorRunAway()
    {
        var forged = "bad\\n2026-08-23 warn: a line the receiver wrote itself" + new string('x', 5000);
        var handler = new StubHttpHandler().Enqueue(
            HttpStatusCode.BadRequest,
            $$"""{"err": "invalid_request", "description": "{{forged}}"}""");
        var outbox = await OutboxWithAsync(new OutboxItem("jti-1", "a.a.a"));
        var logger = new CapturingLogger();

        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver, logger);
        await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        var written = Assert.Single(logger.Written).Text;

        Assert.DoesNotContain('\n', written);
        Assert.DoesNotContain('\r', written);
        Assert.True(written.Length < 600, $"the line grew to {written.Length} characters");

        // The control: the beginning of what the receiver said survives, so the bound above is not
        // satisfied by dropping the description altogether.
        Assert.Contains("bad", written, StringComparison.Ordinal);
    }

    /// <summary>The control: a delivery the receiver accepts writes nothing.</summary>
    /// <remarks>
    /// Without it the assertions above are satisfied by a sender that logs on every pass, which would bury
    /// the refusals it exists to surface.
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

    /// <summary>Keeps what was written, with the two properties a log pipeline filters on.</summary>
    /// <remarks>
    /// The level and the id are kept rather than discarded, because a level below the host's floor and an id
    /// nobody publishes both render the identical sentence while the line reaches nobody.
    /// </remarks>
    private sealed class CapturingLogger : ILogger<PushDeliverySender>
    {
        public List<(LogLevel Level, EventId Event, string Text)> Written { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Written.Add((logLevel, eventId, formatter(state, exception)));

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
        var service = new StreamManagementService(
            store, outbox, dispatcher, options, PolicyFor(options), PollEndpointsOf(options));

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
    /// <summary>
    /// The poll address, taken from the options the way the container would. This fixture names none, so
    /// the service it builds offers no poll delivery - which is what these rows are about, since they
    /// exercise push.
    /// </summary>
    private static PollEndpointLocator PollEndpointsOf(SharedSignalsTransmitterOptions options) => new(options);
}
