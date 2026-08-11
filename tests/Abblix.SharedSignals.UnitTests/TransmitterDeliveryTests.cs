// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Net.Mime;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Abblix.SecurityEvents.Delivery;
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
    private static ReceiverAddressPolicy ReachingTheTestReceiver => new(new SsfTransmitterOptions
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
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver);

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
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver);

        var outcome = await sender.SendPendingAsync(PushStream(), TestContext.Current.CancellationToken);

        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 0, Rejected: 1), outcome);
        Assert.Equal(
            ["jti-2", "jti-3"],
            (await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken))
            .Select(item => item.JwtId));
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
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver);

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
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver);

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
        var sender = new PushDeliverySender(handler.CreateClient(), outbox, ReachingTheTestReceiver);

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
        var options = new SsfTransmitterOptions { Issuer = "https://tr.example.com" };
        var dispatcher = new EventDispatcher(store, outbox, signer, options.Issuer);
        var service = new StreamManagementService(store, outbox, dispatcher, options);

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
}
