// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// What a fan-out tells its caller about the streams it could not reach, and the dispatch limited to those
/// streams that lets the caller try them again without sending the event twice to the streams that have it.
/// </summary>
public class EventDispatcherNotReachedTests
{
    private const string Issuer = "https://tr.example.com";
    private const string Receiver = "receiver-a";
    private const string MembershipChanged = "https://example.com/events/membership-changed";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task AStreamWhoseOutboxFails_IsReportedAsNotReached_AndTheOthersStillGetTheEvent()
    {
        var store = await StoreWithAsync(Stream("s-1"), Stream("s-2"), Stream("s-3"));
        var outbox = new FailingOutbox("s-2");

        var result = await Dispatcher(store, outbox).DispatchAsync(Descriptor(), Cancellation);

        Assert.Equal(2, result.Reached);
        Assert.Equal([new StreamReference(Receiver, "s-2")], result.NotReached);
        Assert.Single(await outbox.PendingAsync(Receiver, "s-3", null, Cancellation));
    }

    [Fact]
    public async Task AnEventNoStreamTakes_ReachesNothing_AndMissesNothing()
    {
        var store = await StoreWithAsync(Stream("s-1", delivered: ["https://example.com/events/other"]));

        var result = await Dispatcher(store, new FailingOutbox()).DispatchAsync(Descriptor(), Cancellation);

        Assert.Equal(0, result.Reached);
        Assert.Empty(result.NotReached);
    }

    /// <summary>
    /// The sharing policy is the host's code, so it can fail like the outbox can: the stream it was asked about
    /// is not reached, and the streams after it are still asked.
    /// </summary>
    [Fact]
    public async Task ASharingPolicyThatFails_LeavesThatStreamNotReached_AndTheFanOutGoesOn()
    {
        var store = await StoreWithAsync(Stream("s-1"), Stream("s-2"));
        var outbox = new FailingOutbox();

        var result = await Dispatcher(store, outbox, new FailingPolicy("s-1")).DispatchAsync(Descriptor(), Cancellation);

        Assert.Equal(1, result.Reached);
        Assert.Equal([new StreamReference(Receiver, "s-1")], result.NotReached);
        Assert.Single(await outbox.PendingAsync(Receiver, "s-2", null, Cancellation));
    }

    /// <summary>
    /// A cancelled fan-out is not a list of streams that failed: it stops and says it was cancelled.
    /// </summary>
    [Fact]
    public async Task ACancelledFanOut_Throws()
    {
        var store = await StoreWithAsync(Stream("s-1"), Stream("s-2"));
        using var cancellation = new CancellationTokenSource();
        var outbox = new FailingOutbox("s-1", () =>
        {
            cancellation.Cancel();
            return new OperationCanceledException(cancellation.Token);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Dispatcher(store, outbox).DispatchAsync(Descriptor(), cancellation.Token));
    }

    [Fact]
    public async Task DispatchingAgainToTheStreamsNotReached_ReachesThemAlone()
    {
        var store = await StoreWithAsync(Stream("s-1"), Stream("s-2"));
        var outbox = new FailingOutbox("s-2");
        var first = await Dispatcher(store, outbox).DispatchAsync(Descriptor(), Cancellation);
        outbox.Recover();

        var retry = await Dispatcher(store, outbox).DispatchAsync(Descriptor(), first.NotReached, Cancellation);

        Assert.Equal(1, retry.Reached);
        Assert.Empty(retry.NotReached);
        Assert.Single(await outbox.PendingAsync(Receiver, "s-1", null, Cancellation));
        Assert.Single(await outbox.PendingAsync(Receiver, "s-2", null, Cancellation));
    }

    /// <summary>
    /// The limited dispatch reads each stream again and runs every check, so it never delivers to a stream that
    /// has been disabled since, one the sharing policy now refuses, or one that no longer exists.
    /// </summary>
    [Fact]
    public async Task DispatchingAgain_HoldsEachStreamToItsCurrentState()
    {
        var store = await StoreWithAsync(
            Stream("disabled", status: StreamStatuses.Disabled),
            Stream("refused"),
            Stream("still-matching"));
        var outbox = new FailingOutbox();
        StreamReference[] streams =
        [
            new(Receiver, "disabled"),
            new(Receiver, "refused"),
            new(Receiver, "deleted"),
            new(Receiver, "still-matching"),
            new(Receiver, "still-matching"),
        ];

        var retry = await Dispatcher(store, outbox, new DenyPolicy("refused"))
            .DispatchAsync(Descriptor(), streams, Cancellation);

        Assert.Equal(1, retry.Reached);
        Assert.Empty(retry.NotReached);
        Assert.Empty(await outbox.PendingAsync(Receiver, "disabled", null, Cancellation));
        Assert.Empty(await outbox.PendingAsync(Receiver, "refused", null, Cancellation));
        Assert.Single(await outbox.PendingAsync(Receiver, "still-matching", null, Cancellation));
    }

    [Fact]
    public async Task AStreamThatCannotBeReadAgain_IsReportedAsNotReached()
    {
        var store = new FailingStreamStore(await StoreWithAsync(Stream("s-1"), Stream("s-2")), "s-1");
        var outbox = new FailingOutbox();

        var retry = await Dispatcher(store, outbox).DispatchAsync(
            Descriptor(), [new(Receiver, "s-1"), new(Receiver, "s-2")], Cancellation);

        Assert.Equal(1, retry.Reached);
        Assert.Equal([new StreamReference(Receiver, "s-1")], retry.NotReached);
    }

    /// <summary>
    /// The payload policy judges the event itself, so it refuses a limited dispatch exactly as it refuses a full
    /// one: before any stream is read.
    /// </summary>
    [Fact]
    public async Task DispatchingAgain_IsRefusedByThePayloadPolicy()
    {
        var store = await StoreWithAsync(Stream("s-1"));
        var outbox = new FailingOutbox();
        var dispatcher = new EventDispatcher(
            NullLogger<EventDispatcher>.Instance,
            store,
            outbox,
            new OptionsTransmitterIdentity(new SharedSignalsTransmitterOptions { Issuer = Issuer }),
            TestInstruments.Create(),
            payloadPolicy: new RefusingPayloadPolicy());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => dispatcher.DispatchAsync(Descriptor(), [new(Receiver, "s-1")], Cancellation));
        Assert.Empty(await outbox.PendingAsync(Receiver, "s-1", null, Cancellation));
    }

    private static StreamState Stream(
        string streamId,
        string status = StreamStatuses.Enabled,
        IReadOnlyList<string>? delivered = null) => new()
    {
        ReceiverId = Receiver,
        Status = status,
        SubjectsMode = StreamSubjectsMode.All,
        AddedSubjects = [],
        RemovedSubjects = [],
        Configuration = new StreamConfiguration
        {
            StreamId = streamId,
            Issuer = Issuer,
            Audiences = [$"https://receiver.example.com/{streamId}"],
            EventsDelivered = delivered ?? [MembershipChanged],
            Delivery = new PollDeliveryMethod(new Uri($"https://tr.example.com/poll/{streamId}")),
        },
    };

    private static SecurityEventDescriptor Descriptor() => new()
    {
        EventType = MembershipChanged,
        Subject = new EmailSubject("jdoe@example.com"),
    };

    private static async Task<InMemoryStreamStore> StoreWithAsync(params StreamState[] streams)
    {
        var store = new InMemoryStreamStore();
        foreach (var stream in streams)
        {
            Assert.True(await store.TryCreateAsync(stream, Cancellation));
        }

        return store;
    }

    private static EventDispatcher Dispatcher(
        IStreamStore store,
        IEventOutbox outbox,
        IEventSharingPolicy? policy = null)
        => new(
            NullLogger<EventDispatcher>.Instance,
            store,
            outbox,
            new OptionsTransmitterIdentity(new SharedSignalsTransmitterOptions { Issuer = Issuer }),
            TestInstruments.Create(),
            policy);

    /// <summary>An outbox that refuses the named stream until it recovers.</summary>
    private sealed class FailingOutbox(string? failingStreamId = null, Func<Exception>? failure = null)
        : IEventOutbox
    {
        private readonly InMemoryEventOutbox _inner = new();
        private string? _failingStreamId = failingStreamId;

        public void Recover() => _failingStreamId = null;

        public Task EnqueueAsync(
            string receiverId, string streamId, OutboxItem item, CancellationToken cancellationToken = default)
        {
            if (streamId != _failingStreamId)
                return _inner.EnqueueAsync(receiverId, streamId, item, cancellationToken);

            throw failure?.Invoke() ?? new HttpRequestException("The outbox store did not answer.");
        }

        public Task<IReadOnlyList<OutboxItem>> PendingAsync(
            string receiverId, string streamId, int? maxCount = null, CancellationToken cancellationToken = default)
            => _inner.PendingAsync(receiverId, streamId, maxCount, cancellationToken);

        public Task AcknowledgeAsync(
            string receiverId,
            string streamId,
            IReadOnlyCollection<string> jwtIds,
            CancellationToken cancellationToken = default)
            => _inner.AcknowledgeAsync(receiverId, streamId, jwtIds, cancellationToken);

        public Task ClearAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
            => _inner.ClearAsync(receiverId, streamId, cancellationToken);
    }

    private sealed class FailingStreamStore(IStreamStore inner, string failingStreamId) : IStreamStore
    {
        public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => inner.TryCreateAsync(stream, cancellationToken);

        public Task<StreamState?> FindAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => streamId == failingStreamId
                ? throw new HttpRequestException("The stream store did not answer.")
                : inner.FindAsync(receiverId, streamId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAsync(
            string receiverId, CancellationToken cancellationToken = default)
            => inner.ListAsync(receiverId, cancellationToken);

        public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
            => inner.ListAllAsync(cancellationToken);

        public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => inner.UpdateAsync(stream, cancellationToken);

        public Task<bool> DeleteAsync(
            string receiverId, string streamId, CancellationToken cancellationToken = default)
            => inner.DeleteAsync(receiverId, streamId, cancellationToken);
    }

    private sealed class FailingPolicy(string failingStreamId) : IEventSharingPolicy
    {
        public Task<bool> IsSharingPermittedAsync(
            StreamState stream,
            SecurityEventDescriptor descriptor,
            CancellationToken cancellationToken = default)
            => stream.StreamId == failingStreamId
                ? throw new InvalidOperationException("The policy store did not answer.")
                : Task.FromResult(true);
    }

    private sealed class DenyPolicy(string deniedStreamId) : IEventSharingPolicy
    {
        public Task<bool> IsSharingPermittedAsync(
            StreamState stream,
            SecurityEventDescriptor descriptor,
            CancellationToken cancellationToken = default)
            => Task.FromResult(stream.StreamId != deniedStreamId);
    }

    private sealed class RefusingPayloadPolicy : IEventPayloadPolicy
    {
        public string? RefusalOf(string eventType, IEventPayload? payload) => "Refused by this deployment.";
    }
}
