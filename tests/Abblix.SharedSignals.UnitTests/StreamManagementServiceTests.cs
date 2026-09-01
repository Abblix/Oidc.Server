// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Time.Testing;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the transmitter's management semantics per SSF 1.0 Section 8.1: what a create supplies
/// and refuses, what PATCH leaves alone and PUT deletes, how status changes treat the held
/// queue, the anti-probing posture of the subject endpoints, and the verification throttle.
/// </summary>
public class StreamManagementServiceTests
{
    private const string Receiver = "receiver-a";
    private const string TypeA = "https://example.com/events/type-a";
    private const string TypeB = "https://example.com/events/type-b";

    private sealed class StubSigner : ISecurityEventTokenSigner
    {
        public List<SecurityEventToken> Signed { get; } = [];

        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        {
            Signed.Add(token);
            return Task.FromResult($"signed.{token.JwtId}");
        }
    }

    /// <summary>
    /// A store that takes every call except the conditional write, so an update reaches the end of
    /// the retry loop with nothing written.
    /// </summary>
    private sealed class RefusingUpdates(IStreamStore inner) : IStreamStore
    {
        public bool Refuse { get; set; }

        public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => inner.TryCreateAsync(stream, cancellationToken);

        public Task<StreamState?> FindAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.FindAsync(receiverId, streamId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAsync(
            string receiverId, CancellationToken cancellationToken = default)
            => inner.ListAsync(receiverId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
            => inner.ListAllAsync(cancellationToken);

        public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => Refuse ? Task.FromResult(false) : inner.UpdateAsync(stream, cancellationToken);

        public Task<bool> DeleteAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.DeleteAsync(receiverId, streamId, cancellationToken);
    }

    private sealed record Harness(
        StreamManagementService Service,
        InMemoryStreamStore Store,
        InMemoryEventOutbox Outbox,
        StubSigner Signer,
        FakeTimeProvider Clock);

    private static SharedSignalsTransmitterOptions DefaultOptions() => new()
    {
        Issuer = "https://tr.example.com",
        EventsSupported = [TypeA, TypeB],
        PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
        MinVerificationInterval = TimeSpan.FromMinutes(5),
    };

    private static Harness CreateHarness() => CreateHarness(DefaultOptions());

    private static Harness CreateHarness(SharedSignalsTransmitterOptions options)
    {
        var store = new InMemoryStreamStore();
        var outbox = new InMemoryEventOutbox();
        var signer = new StubSigner();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754200000));
        var dispatcher = new EventDispatcher(
            NullLogger<EventDispatcher>.Instance, store, outbox, signer, options.Issuer, clock: clock);

        return new Harness(
            new StreamManagementService(
                store, outbox, dispatcher, options, PolicyFor(options), PollEndpointsOf(options), clock),
            store, outbox, signer, clock);
    }

    private static async Task<StreamConfiguration> CreatedStreamAsync(
        Harness harness,
        CreateStreamRequest? request = null)
    {
        var created = await harness.Service.CreateStreamAsync(
            Receiver,
            request ?? new CreateStreamRequest { EventsRequested = [TypeA] },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return created.Body!;
    }

    [Fact]
    public async Task Create_SuppliesTheTransmitterHalf_AndDefaultsToPoll()
    {
        var harness = CreateHarness();

        var configuration = await CreatedStreamAsync(harness, new CreateStreamRequest
        {
            // TypeB is requested but the receiver also asks for something unsupported, which
            // the transmitter ignores (Section 8.1.1): delivered = supported ∩ requested.
            EventsRequested = [TypeB, "https://example.com/events/unknown"],
            Description = "Stream for Receiver A",
        });

        Assert.Equal("https://tr.example.com", configuration.Issuer);
        Assert.Equal([Receiver], configuration.Audiences);
        Assert.Equal([TypeB], configuration.EventsDelivered);
        Assert.Equal("Stream for Receiver A", configuration.Description);

        // No delivery proposed means poll, with the endpoint URL the transmitter's own
        // (Section 8.1.1.1).
        var poll = Assert.IsType<PollDeliveryMethod>(configuration.Delivery);
        Assert.Equal(
            new Uri($"https://tr.example.com/ssf/poll/{configuration.StreamId}"),
            poll.EndpointUrl);
    }

    [Fact]
    public async Task Create_SecondStream_ConflictsUnderTheSingleStreamPolicy()
    {
        var harness = CreateHarness();
        await CreatedStreamAsync(harness);

        var second = await harness.Service.CreateStreamAsync(
            Receiver, new CreateStreamRequest(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Create_PollAskedOfAPushOnlyTransmitter_IsRefused()
    {
        var harness = CreateHarness(new SharedSignalsTransmitterOptions
        {
            Issuer = "https://tr.example.com",
            EventsSupported = [TypeA],
        });

        var result = await harness.Service.CreateStreamAsync(
            Receiver, new CreateStreamRequest(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
    }

    /// <summary>
    /// An update the store would not take answers "202 Accepted", and never "409 Conflict".
    /// </summary>
    /// <remarks>
    /// SSF 1.0 lists 202 in both update tables - Sections 8.1.1.3 and 8.1.2.2 - for a request
    /// accepted and not processed, and 8.1.2.2 makes it a MUST for a transmitter that cannot decide
    /// whether to complete one. 409 belongs to the create endpoint of Section 8.1.1.1 and means "you
    /// already have a stream", which is what a receiver branching on the code would be told here:
    /// that everything is in order, while its change is gone. A discriminator in the body does not
    /// repair that, because the code is what gets branched on.
    /// </remarks>
    [Fact]
    public async Task AnUpdateTheStoreRefuses_Answers202_NeverConflict()
    {
        var ct = TestContext.Current.CancellationToken;
        var options = DefaultOptions();
        var store = new RefusingUpdates(new InMemoryStreamStore());
        var outbox = new InMemoryEventOutbox();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754200000));
        var dispatcher = new EventDispatcher(
            NullLogger<EventDispatcher>.Instance, store, outbox, new StubSigner(), options.Issuer, clock: clock);
        var service = new StreamManagementService(
            store, outbox, dispatcher, options, PolicyFor(options), PollEndpointsOf(options), clock);

        var created = await service.CreateStreamAsync(
            Receiver, new CreateStreamRequest { EventsRequested = [TypeA] }, ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        store.Refuse = true;

        var updated = await service.UpdateStreamAsync(
            Receiver,
            new UpdateStreamRequest { StreamId = created.Body!.StreamId, EventsRequested = [TypeB] },
            ct);

        // The create endpoint's "you already have a stream" is what this used to say, and it is the
        // whole reason the code changed.
        Assert.Equal(HttpStatusCode.Accepted, updated.StatusCode);

        // And nothing was written, whatever the code says: 202 promises the receiver that repeating
        // the call is the way forward, which is only true while the change really is absent.
        store.Refuse = false;
        var read = await service.GetStreamAsync(Receiver, created.Body.StreamId, ct);
        Assert.Equal([TypeA], read.Body!.EventsDelivered);
    }

    /// <summary>
    /// A contended subject or verification request must NOT answer any 2xx, 202 included.
    /// </summary>
    /// <remarks>
    /// The error tables for these endpoints - Sections 8.1.3.2, 8.1.3.3 and 8.1.4.2 - list no 202,
    /// and the reason to care is one layer further on: <c>StreamManagementClient</c> answers all
    /// three of these calls with a bool, false only on 429, so every other 2xx becomes "done". A
    /// contended add-subject reported as done leaves the receiver believing it is subscribed to a
    /// subject nothing was ever written for, and no event about that subject will ever arrive -
    /// a security signal announced as delivered and silently dropped.
    /// </remarks>
    [Fact]
    public async Task AContendedSubjectOrVerificationRequest_IsNeverAnswered2xx()
    {
        var ct = TestContext.Current.CancellationToken;
        var options = DefaultOptions();
        var store = new RefusingUpdates(new InMemoryStreamStore());
        var outbox = new InMemoryEventOutbox();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754200000));
        var dispatcher = new EventDispatcher(
            NullLogger<EventDispatcher>.Instance, store, outbox, new StubSigner(), options.Issuer, clock: clock);
        var service = new StreamManagementService(
            store, outbox, dispatcher, options, PolicyFor(options), PollEndpointsOf(options), clock);

        var created = await service.CreateStreamAsync(
            Receiver, new CreateStreamRequest { EventsRequested = [TypeA] }, ct);
        var streamId = created.Body!.StreamId;

        store.Refuse = true;

        var added = await service.AddSubjectAsync(
            Receiver,
            new AddSubjectRequest { StreamId = streamId, Subject = new OpaqueSubject("subject-1") },
            ct);
        var removed = await service.RemoveSubjectAsync(
            Receiver,
            new RemoveSubjectRequest { StreamId = streamId, Subject = new OpaqueSubject("subject-1") },
            ct);
        var verified = await service.RequestVerificationAsync(
            Receiver, new VerificationRequest { StreamId = streamId }, ct);

        foreach (var refused in new[] { added.StatusCode, removed.StatusCode, verified.StatusCode })
        {
            Assert.False(
                (int)refused is >= 200 and <= 299,
                $"A discarded write answered {(int)refused}, which the receiver reads as success.");
        }
    }

    [Fact]
    public async Task Update_ChangesOnlyWhatWasSent()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness, new CreateStreamRequest
        {
            EventsRequested = [TypeA],
            Description = "original",
        });

        var updated = await harness.Service.UpdateStreamAsync(
            Receiver,
            new UpdateStreamRequest { StreamId = created.StreamId, EventsRequested = [TypeB] },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal([TypeB], updated.Body!.EventsDelivered);
        // The description was absent from the PATCH, so it stays (Section 8.1.1.3).
        Assert.Equal("original", updated.Body.Description);
    }

    [Fact]
    public async Task Replace_DeletesTheAbsent_AndRefusesToDeleteTheDelivery()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness, new CreateStreamRequest
        {
            EventsRequested = [TypeA],
            Description = "original",
        });

        var replaced = await harness.Service.ReplaceStreamAsync(
            Receiver,
            new UpdateStreamRequest
            {
                StreamId = created.StreamId,
                Delivery = new PollDeliveryMethod(),
                EventsRequested = [TypeA],
            },
            TestContext.Current.CancellationToken);

        // The description was absent from the PUT body: deleted (Section 8.1.1.4).
        Assert.Equal(HttpStatusCode.OK, replaced.StatusCode);
        Assert.Null(replaced.Body!.Description);

        var withoutDelivery = await harness.Service.ReplaceStreamAsync(
            Receiver,
            new UpdateStreamRequest { StreamId = created.StreamId },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, withoutDelivery.StatusCode);
    }

    [Fact]
    public async Task Delete_DropsTheStreamAndItsQueue()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);
        await harness.Outbox.EnqueueAsync(
            created.StreamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

        var deleted = await harness.Service.DeleteStreamAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.Empty(await harness.Outbox.PendingAsync(
            created.StreamId, null, TestContext.Current.CancellationToken));
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await harness.Service.DeleteStreamAsync(
                Receiver, created.StreamId, TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task StatusUpdate_ValidatesTheValue_AndDisablingDropsTheHeldQueue()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);
        await harness.Outbox.EnqueueAsync(
            created.StreamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

        var invalid = await harness.Service.UpdateStreamStatusAsync(
            Receiver,
            new StreamStatus { StreamId = created.StreamId, Status = "hibernating" },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        var disabled = await harness.Service.UpdateStreamStatusAsync(
            Receiver,
            new StreamStatus { StreamId = created.StreamId, Status = StreamStatuses.Disabled },
            TestContext.Current.CancellationToken);

        // "will not hold any events for later transmission" (Section 8.1.2.1).
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        Assert.Equal(StreamStatuses.Disabled, disabled.Body!.Status);
        Assert.Empty(await harness.Outbox.PendingAsync(
            created.StreamId, null, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A Complex Subject naming no member is refused: SSF 1.0 Section 3.3 requires at least one,
    /// and here the rule is load-bearing rather than formal.
    /// </summary>
    /// <remarks>
    /// Matching asks whether every member the stream named agrees with the event's, so a subject
    /// that named none agrees with everything. Added to a stream in the conservative default mode -
    /// the one chosen so that a misconfigured stream leaks nothing - one such request would turn it
    /// into a subscription to every event the transmitter has.
    /// </remarks>
    [Fact]
    public async Task Subjects_AnEmptyComplexSubject_IsRefused_RatherThanCoveringEverything()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);

        var addition = await harness.Service.AddSubjectAsync(
            Receiver,
            new AddSubjectRequest { StreamId = created.StreamId, Subject = new ComplexSubject() },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, addition.StatusCode);

        var state = await harness.Store.FindAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);
        Assert.Empty(state!.AddedSubjects);
    }

    [Fact]
    public async Task Subjects_AdditionCovers_AndRemovalAnswersSuccessEvenForTheNeverAdded()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);
        var subject = new EmailSubject("jdoe@example.com");

        var addition = await harness.Service.AddSubjectAsync(
            Receiver,
            new AddSubjectRequest { StreamId = created.StreamId, Subject = subject },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, addition.StatusCode);

        var state = await harness.Store.FindAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);
        var added = Assert.Single(state!.AddedSubjects);
        Assert.True(added.Verified);

        // Removing a subject nobody added still answers success: a 404 here is the probing
        // signal Section 9.1 warns about.
        var removal = await harness.Service.RemoveSubjectAsync(
            Receiver,
            new RemoveSubjectRequest
            {
                StreamId = created.StreamId,
                Subject = new EmailSubject("stranger@example.com"),
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, removal.StatusCode);
    }

    [Fact]
    public async Task AllMode_RemovalCarvesOut_AndReAdditionRestores()
    {
        var harness = CreateHarness(new SharedSignalsTransmitterOptions
        {
            Issuer = "https://tr.example.com",
            EventsSupported = [TypeA],
            DefaultSubjectsMode = StreamSubjectsMode.All,
            PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
        });
        var created = await CreatedStreamAsync(harness);
        var subject = new EmailSubject("optout@example.com");

        await harness.Service.RemoveSubjectAsync(
            Receiver,
            new RemoveSubjectRequest { StreamId = created.StreamId, Subject = subject },
            TestContext.Current.CancellationToken);

        var carved = await harness.Store.FindAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);
        Assert.Single(carved!.RemovedSubjects);

        await harness.Service.AddSubjectAsync(
            Receiver,
            new AddSubjectRequest { StreamId = created.StreamId, Subject = subject },
            TestContext.Current.CancellationToken);

        var restored = await harness.Store.FindAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);
        Assert.Empty(restored!.RemovedSubjects);
    }

    [Fact]
    public async Task Verification_EnqueuesTheStreamsOwnEvent_AndThrottlesInsideTheInterval()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);

        var first = await harness.Service.RequestVerificationAsync(
            Receiver,
            new VerificationRequest { StreamId = created.StreamId, State = "opaque-state" },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);

        // The SET's subject is the stream itself, opaque (Section 8.1.4.1), and the state is
        // echoed in the event payload.
        var minted = Assert.Single(harness.Signer.Signed);
        Assert.Equal(created.StreamId, Assert.IsType<OpaqueSubject>(minted.GetSubjectId()).Id);
        Assert.Single(await harness.Outbox.PendingAsync(
            created.StreamId, null, TestContext.Current.CancellationToken));

        var throttled = await harness.Service.RequestVerificationAsync(
            Receiver,
            new VerificationRequest { StreamId = created.StreamId },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, throttled.StatusCode);

        harness.Clock.Advance(TimeSpan.FromMinutes(6));
        var afterInterval = await harness.Service.RequestVerificationAsync(
            Receiver,
            new VerificationRequest { StreamId = created.StreamId },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, afterInterval.StatusCode);
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
    /// The poll address, taken from the options the way the container would. Most fixtures here name it
    /// through <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/>, and one deliberately
    /// does not - the row that refuses a poll create on a push-only transmitter. A host that maps the
    /// endpoints has the address declared by the mapping instead, which is covered end to end.
    /// </summary>
    private static PollEndpointLocator PollEndpointsOf(SharedSignalsTransmitterOptions options) => new(options);
}
