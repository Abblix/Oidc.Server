// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The transmitter's half of the Event Stream Management API (SSF 1.0 Section 8.1): every
/// operation from an authenticated receiver identity and a typed request to the
/// <see cref="ManagementResult{TBody}"/> a host adapter renders. The store persists, the
/// adapter transports and authenticates - the SSF semantics live here, once.
/// </summary>
/// <remarks>
/// Echoed transmitter-supplied members are the one place this service is deliberately more
/// lenient than SSF 1.0 Sections 8.1.1.3-8.1.1.4 permit: the typed update request carries the
/// receiver-supplied members alone, so an echoed transmitter-supplied member never reaches the
/// comparison the sections describe - it is dropped at binding, which the same sections allow
/// for the MISSING case. A receiver echoing a stale value is thus tolerated rather than told
/// 400.
/// </remarks>
/// <param name="store">Where streams live.</param>
/// <param name="outbox">The per-stream queues, dropped with their stream.</param>
/// <param name="dispatcher">Mints and enqueues the framework's own signals.</param>
/// <param name="options">The deployment's one-time decisions.</param>
/// <param name="addressPolicy">
/// Judges the delivery address a receiver proposes. The same policy the sender consults, deliberately:
/// an address refused at delivery is refused for a reason that was already true when the receiver named
/// it, and answering 201 to a stream that can never be delivered to tells the receiver nothing it can
/// act on - the refusal then lives only in the transmitter's log.</param>
/// <param name="pollEndpoints">Where a poll stream is polled - this transmitter's own address, and the
/// one member of a stream's delivery it supplies rather than receives.</param>
/// <param name="clock">Measures the verification throttle; null takes the system clock.</param>
public sealed class StreamManagementService(
    IStreamStore store,
    IEventOutbox outbox,
    EventDispatcher dispatcher,
    SharedSignalsTransmitterOptions options,
    ReceiverAddressPolicy addressPolicy,
    PollEndpointLocator pollEndpoints,
    TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private readonly StreamDeliveryFactory _deliveries = new(addressPolicy, pollEndpoints);

    /// <summary>
    /// Creates a stream for the receiver (SSF 1.0 Section 8.1.1.1): the transmitter supplies
    /// identity, audience and the delivered-events intersection; the receiver's proposal
    /// supplies the rest.
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="request">The receiver-supplied half of the configuration.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<StreamConfiguration>> CreateStreamAsync(
        string receiverId,
        CreateStreamRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(receiverId);
        ArgumentNullException.ThrowIfNull(request);

        var singleStream = new SingleStreamPerReceiverRule(store, options);
        if (await singleStream.ForbidsAnotherAsync(receiverId, cancellationToken))
        {
            return ManagementResult<StreamConfiguration>.Conflict(
                "The receiver already has a stream, and this transmitter allows one per receiver "
                + "(SSF 1.0 Section 8.1.1.1); read it and update or replace what differs.");
        }

        var streamId = StreamConfigurations.NewStreamId();

        var accepted = _deliveries.Create(request.Delivery, streamId);
        if (accepted.Body is not { } delivery)
        {
            return StreamDeliveryFactory.RefusalOf(accepted);
        }

        var configuration = StreamConfigurations.New(
            options, dispatcher.Issuer, receiverId, streamId, request, delivery);

        var created = new StreamState
        {
            ReceiverId = receiverId,
            Configuration = configuration,
            SubjectsMode = options.DefaultSubjectsMode,
        };

        if (!await store.TryCreateAsync(created, cancellationToken))
        {
            return ManagementResult<StreamConfiguration>.Conflict(
                "A stream with the generated identifier already exists.");
        }

        if (await singleStream.LosesToAnotherAsync(receiverId, streamId, cancellationToken))
        {
            await store.DeleteAsync(receiverId, streamId, cancellationToken);
            return ManagementResult<StreamConfiguration>.Conflict(
                "The receiver already has a stream, and this transmitter allows one per receiver "
                + "(SSF 1.0 Section 8.1.1.1); read it and update or replace what differs.");
        }

        return ManagementResult<StreamConfiguration>.Created(configuration);
    }

    /// <summary>
    /// Reads one stream's configuration (SSF 1.0 Section 8.1.1.2).
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="streamId">The stream to read.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<StreamConfiguration>> GetStreamAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => await store.FindAsync(receiverId, streamId, cancellationToken) is { } stream
            ? ManagementResult<StreamConfiguration>.Ok(stream.Configuration)
            : NoSuchStream<StreamConfiguration>(streamId);

    /// <summary>
    /// Lists the receiver's streams (SSF 1.0 Section 8.1.1.2); the empty list is a receiver
    /// with no streams, never an error.
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<IReadOnlyList<StreamConfiguration>>> ListStreamsAsync(
        string receiverId,
        CancellationToken cancellationToken = default)
        => ManagementResult<IReadOnlyList<StreamConfiguration>>.Ok(
            (await store.ListAsync(receiverId, cancellationToken))
            .Select(stream => stream.Configuration)
            .ToArray());

    /// <summary>
    /// Updates a stream: present receiver-supplied members change, absent ones stay
    /// (SSF 1.0 Section 8.1.1.3).
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="request">The stream identifier and the members to change.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<StreamConfiguration>> UpdateStreamAsync(
        string receiverId,
        UpdateStreamRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (await store.FindAsync(receiverId, request.StreamId, cancellationToken) is not { } stream)
        {
            return NoSuchStream<StreamConfiguration>(request.StreamId);
        }

        var configuration = stream.Configuration;

        if (request.Delivery is { } proposedDelivery)
        {
            var accepted = _deliveries.Create(proposedDelivery, stream.StreamId);
            if (accepted.Body is not { } delivery)
            {
                return StreamDeliveryFactory.RefusalOf(accepted);
            }

            configuration = configuration with { Delivery = delivery };
        }

        if (request.EventsRequested is { } requested)
        {
            configuration = configuration with
            {
                EventsRequested = requested,
                EventsDelivered = StreamConfigurations.DeliveredOf(options, requested),
            };
        }

        if (request.Description is { } description)
        {
            configuration = configuration with { Description = description };
        }

        return await SaveConfigurationAsync(stream, configuration, cancellationToken);
    }

    /// <summary>
    /// Replaces a stream's receiver-supplied configuration whole: a member absent from the
    /// request is deleted (SSF 1.0 Section 8.1.1.4) - except the delivery, without which a
    /// stream cannot operate, so its absence is refused rather than read as deletion.
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="request">The stream identifier and the full receiver-supplied set.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<StreamConfiguration>> ReplaceStreamAsync(
        string receiverId,
        UpdateStreamRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (await store.FindAsync(receiverId, request.StreamId, cancellationToken) is not { } stream)
        {
            return NoSuchStream<StreamConfiguration>(request.StreamId);
        }

        if (request.Delivery is null)
        {
            return ManagementResult<StreamConfiguration>.BadRequest(
                "A replacement carries the full receiver-supplied set, and a stream cannot exist "
                + "without a delivery method (SSF 1.0 Section 8.1.1.4).");
        }

        var accepted = _deliveries.Create(request.Delivery, stream.StreamId);
        if (accepted.Body is not { } delivery)
        {
            return StreamDeliveryFactory.RefusalOf(accepted);
        }

        var configuration = stream.Configuration with
        {
            Delivery = delivery,
            EventsRequested = request.EventsRequested,
            EventsDelivered = StreamConfigurations.DeliveredOf(options, request.EventsRequested),
            Description = request.Description,
        };

        return await SaveConfigurationAsync(stream, configuration, cancellationToken);
    }

    /// <summary>
    /// Deletes a stream and drops its queue (SSF 1.0 Section 8.1.1.5).
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="streamId">The stream to delete.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<object>> DeleteStreamAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
    {
        if (!await store.DeleteAsync(receiverId, streamId, cancellationToken))
        {
            return NoSuchStream<object>(streamId);
        }

        await outbox.ClearAsync(receiverId, streamId, cancellationToken);
        return ManagementResult<object>.NoContent();
    }

    /// <summary>
    /// Reads a stream's status (SSF 1.0 Section 8.1.2.1).
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="streamId">The stream whose status is being queried.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<StreamStatus>> GetStreamStatusAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => await store.FindAsync(receiverId, streamId, cancellationToken) is { } stream
            ? ManagementResult<StreamStatus>.Ok(StatusOf(stream))
            : NoSuchStream<StreamStatus>(streamId);

    /// <summary>
    /// Updates a stream's status at the receiver's request (SSF 1.0 Section 8.1.2.2). A
    /// receiver-driven change sends no stream-updated event - Section 8.1.5 binds the
    /// transmitter's OWN changes only. Disabling drops the held queue: a disabled stream
    /// "will not hold any events" (Section 8.1.2.1).
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="request">The stream, the new status, and optionally why.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<StreamStatus>> UpdateStreamStatusAsync(
        string receiverId,
        StreamStatus request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Status is not (StreamStatuses.Enabled or StreamStatuses.Paused or StreamStatuses.Disabled))
        {
            return ManagementResult<StreamStatus>.BadRequest(
                $"'{request.Status}' is not a stream status (SSF 1.0 Section 8.1.2.1).");
        }

        var (updated, missing) = await MutateAsync(
            receiverId,
            request.StreamId,
            stream => stream with { Status = request.Status, StatusReason = request.Reason },
            cancellationToken);

        if (missing)
            return NoSuchStream<StreamStatus>(request.StreamId);

        if (updated is null)
            return AcceptedNotProcessed<StreamStatus>(request.StreamId);

        if (request.Status == StreamStatuses.Disabled)
        {
            await outbox.ClearAsync(updated.ReceiverId, updated.StreamId, cancellationToken);
        }

        return ManagementResult<StreamStatus>.Ok(StatusOf(updated));
    }

    /// <summary>
    /// Adds a subject to a stream (SSF 1.0 Section 8.1.3.2). Success asserts nothing about the
    /// subject being known - the anti-probing posture of Section 9.1 by construction, since
    /// this service accepts any well-formed subject as a statement of interest.
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="request">The stream, the subject, and optionally whether it is verified;
    /// omitted means verified (Section 8.1.3.2).</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<object>> AddSubjectAsync(
        string receiverId,
        AddSubjectRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // A Complex Subject "MUST contain at least one Simple Subject Member" (SSF 1.0 Section 3.3),
        // and here that rule is not a formality: matching asks whether every member the stream
        // named agrees with the event's, so a subject that named none agrees with every event.
        // Added to a stream whose mode is None - the conservative default, chosen so that a
        // misconfigured stream leaks nothing - one such request turns it into a subscription to
        // everything. The shape is refused where it arrives, since nothing downstream can tell it
        // from a deliberate partial match.
        if (StreamSubjectCommands.NamesNothing(request.Subject))
        {
            return ManagementResult<object>.BadRequest(
                "A complex subject carries at least one member (SSF 1.0 Section 3.3); one with none "
                + "would match every event on the stream.");
        }

        var (written, missing) = await MutateAsync(
            receiverId,
            request.StreamId,
            StreamSubjectCommands.Add(request.Subject, request.Verified ?? true),
            cancellationToken);

        if (missing)
            return NoSuchStream<object>(request.StreamId);

        return written is null
            ? Contended<object>(request.StreamId)
            : ManagementResult<object>.Ok();
    }

    /// <summary>
    /// Removes a subject from a stream (SSF 1.0 Section 8.1.3.3). Removing what was never
    /// added still answers success: a 404 for an unrecognized subject is exactly the probing
    /// signal Section 9.1 warns about, and staying silent is the option it offers.
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="request">The stream and the subject.</param>
    /// <param name="cancellationToken">Cancels store I/O.</param>
    public async Task<ManagementResult<object>> RemoveSubjectAsync(
        string receiverId,
        RemoveSubjectRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var (written, missing) = await MutateAsync(
            receiverId,
            request.StreamId,
            StreamSubjectCommands.Remove(request.Subject),
            cancellationToken);

        if (missing)
            return NoSuchStream<object>(request.StreamId);

        return written is null
            ? Contended<object>(request.StreamId)
            : ManagementResult<object>.NoContent();
    }

    /// <summary>
    /// Triggers a Verification Event over a stream (SSF 1.0 Section 8.1.4.2): the event is
    /// enqueued with the stream's own opaque identifier as its subject and the receiver's
    /// "state" echoed, and requests inside "min_verification_interval" are throttled.
    /// </summary>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="request">The stream and optionally the state to echo.</param>
    /// <param name="cancellationToken">Cancels store I/O and the enqueue.</param>
    public async Task<ManagementResult<object>> RequestVerificationAsync(
        string receiverId,
        VerificationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (await store.FindAsync(receiverId, request.StreamId, cancellationToken) is not { } stream)
        {
            return NoSuchStream<object>(request.StreamId);
        }

        var now = _clock.GetUtcNow();
        if (options.MinVerificationInterval is { } interval
            && stream.LastVerificationRequestAt is { } last
            && now - last < interval)
        {
            return ManagementResult<object>.TooManyRequests(
                "Verification was requested more often than the stream's "
                + $"'{StreamMemberNames.MinVerificationInterval}' permits (SSF 1.0 Section 8.1.4.2).");
        }

        // The throttle is written BEFORE the event is minted, and the answer follows what the write
        // reported. Dispatching first spends the irreversible half - an event queued cannot be
        // unqueued - on a stream whose record may already be gone, and leaves the throttle unwritten
        // for as long as the dispatch takes, which is the window two concurrent requests both pass.
        var (throttled, missing) = await MutateAsync(
            receiverId,
            request.StreamId,
            current => current with { LastVerificationRequestAt = now },
            cancellationToken);

        if (missing)
            return NoSuchStream<object>(request.StreamId);

        if (throttled is null)
            return Contended<object>(request.StreamId);

        await dispatcher.DispatchToStreamAsync(
            stream,
            StreamEventDescriptors.Verification(stream.StreamId, request.State),
            cancellationToken: cancellationToken);

        return ManagementResult<object>.NoContent();
    }

    /// <summary>
    /// Changes a stream's status on the transmitter's OWN initiative - the door SSF 1.0
    /// Section 8.1.5 governs, as opposed to the receiver-driven
    /// <see cref="UpdateStreamStatusAsync"/>. The stream-updated event escorts the change: for
    /// a pause or disable it is enqueued as a status announcement, the one kind of item
    /// delivery carries over a stopped stream, and for a disable the held queue is dropped
    /// FIRST so the announcement is not dropped with it.
    /// </summary>
    /// <param name="receiverId">The receiver whose stream is being changed.</param>
    /// <param name="streamId">The stream being changed.</param>
    /// <param name="status">The new status, one of <see cref="StreamStatuses"/>.</param>
    /// <param name="reason">Why the transmitter changed it, for the event and the status
    /// document.</param>
    /// <param name="cancellationToken">Cancels store I/O and the enqueue.</param>
    /// <returns>True when the stream was found and changed; false when no such stream exists,
    /// or its status already was the requested one - a no-op announces nothing.</returns>
    /// <exception cref="ArgumentException">
    /// The status value is not one of <see cref="StreamStatuses"/>: the caller here is the
    /// transmitter's own code, so a bad value is a programming error, not wire input.
    /// </exception>
    public async Task<bool> ChangeStreamStatusAsync(
        string receiverId,
        string streamId,
        string status,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        if (status is not (StreamStatuses.Enabled or StreamStatuses.Paused or StreamStatuses.Disabled))
        {
            throw new ArgumentException(
                $"'{status}' is not a stream status (SSF 1.0 Section 8.1.2.1).", nameof(status));
        }

        if (await store.FindAsync(receiverId, streamId, cancellationToken) is not { } stream
            || stream.Status == status)
        {
            return false;
        }

        // The status is written FIRST, and nothing irreversible happens until it succeeds. The
        // queue is dropped and the announcement minted afterwards, because neither can be undone:
        // a concurrent delete used to leave this method reporting that nothing happened, having
        // already destroyed the queue and enqueued an announcement onto a stream that was gone.
        var (updated, _) = await MutateAsync(
            receiverId,
            streamId,
            current => current with { Status = status, StatusReason = reason },
            cancellationToken);

        if (updated is null)
            return false;

        if (status == StreamStatuses.Disabled)
        {
            // "will not hold any events" (Section 8.1.2.1) - and dropped before the
            // announcement is enqueued, so the announcement survives the drop.
            await outbox.ClearAsync(stream.ReceiverId, stream.StreamId, cancellationToken);
        }

        await dispatcher.DispatchToStreamAsync(
            stream,
            StreamEventDescriptors.StreamUpdated(stream.StreamId, status, reason),
            asStatusAnnouncement: true,
            cancellationToken);

        return true;
    }

    private async Task<ManagementResult<StreamConfiguration>> SaveConfigurationAsync(
        StreamState stream,
        StreamConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var (written, missing) = await MutateAsync(
            stream.ReceiverId,
            stream.StreamId,
            current => current with { Configuration = configuration },
            cancellationToken);

        if (missing)
            return NoSuchStream<StreamConfiguration>(stream.StreamId);

        return written is null
            ? AcceptedNotProcessed<StreamConfiguration>(stream.StreamId)
            : ManagementResult<StreamConfiguration>.Ok(configuration);
    }

    private static StreamStatus StatusOf(StreamState stream) => new()
    {
        StreamId = stream.StreamId,
        Status = stream.Status,
        Reason = stream.StatusReason,
    };

    /// <summary>
    /// How many times a mutation re-reads and re-applies before giving up on a contended stream.
    /// </summary>
    /// <remarks>
    /// Small on purpose. Each attempt is a fresh read, so the loop converges as soon as writers
    /// stop arriving; a stream contended past this is not slow, it is being written by something
    /// that will not stop, and answering at all tells the receiver that rather than blocking on it.
    /// </remarks>
    private const int MutationAttempts = 4;

    /// <summary>
    /// Reads a stream, applies <paramref name="change"/> and writes it back, re-reading when
    /// another writer got in first.
    /// </summary>
    /// <remarks>
    /// Every mutation in this service is a read-modify-write, and the store refuses a write whose
    /// version is not the one on record - so without this loop two concurrent additions would end
    /// with one of them refused rather than one of them lost. Re-reading is what turns the refusal
    /// into the second addition landing on top of the first.
    /// </remarks>
    /// <returns>
    /// The written state; or null with <c>Missing</c> when there is no such stream, and null
    /// without it when the stream was contended throughout.</returns>
    private async Task<(StreamState? Written, bool Missing)> MutateAsync(
        string receiverId,
        string streamId,
        Func<StreamState, StreamState> change,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MutationAttempts; attempt++)
        {
            if (await store.FindAsync(receiverId, streamId, cancellationToken) is not { } stream)
                return (null, true);

            var changed = change(stream);
            if (await store.UpdateAsync(changed, cancellationToken))
                return (changed, false);
        }

        return (null, false);
    }

    /// <summary>
    /// The answer to a contended CONFIGURATION or STATUS update: the receiver may repeat the call.
    /// </summary>
    /// <remarks>
    /// "202 Accepted", the code SSF 1.0 lists for exactly this outcome in the update tables of
    /// Sections 8.1.1.3, 8.1.1.4 and 8.1.2.2. Not "409 Conflict", however much a lost race sounds
    /// like one: the specification spends that code on the neighbouring create endpoint for "you
    /// already have a stream", so a receiver reading it here is told the opposite of what happened -
    /// its change did not land, and it hears that everything is in order. That is not an ambiguity a
    /// discriminator in the body would fix, because the code is what a receiver branches on.
    /// </remarks>
    private static ManagementResult<TBody> AcceptedNotProcessed<TBody>(string streamId)
        => ManagementResult<TBody>.Accepted(
            $"The stream '{streamId}' is being changed by someone else; nothing was written. Read "
            + "it again and repeat the call.");

    /// <summary>
    /// The answer to a contended SUBJECT or VERIFICATION request, where 202 is not available.
    /// </summary>
    /// <remarks>
    /// The error tables for these endpoints - Sections 8.1.3.2, 8.1.3.3 and 8.1.4.2 - list no 202,
    /// and lending them one would be worse than imprecise. Every 2xx is a success to
    /// <c>StreamManagementClient</c>, which answers these three calls with a plain bool: a 202 there
    /// is reported to the receiver as a subject it is now subscribed to, or a verification event on
    /// its way, when the write was in fact discarded. A signal nobody will ever deliver, announced
    /// as delivered, is a worse failure than a refusal in a code the table does not name - so these
    /// keep answering loudly, and the receiver keeps finding out.
    /// </remarks>
    private static ManagementResult<TBody> Contended<TBody>(string streamId)
        => ManagementResult<TBody>.Conflict(
            $"The stream '{streamId}' is being changed by someone else; nothing was written. Read "
            + "it again and repeat the call.");

    private static ManagementResult<TBody> NoSuchStream<TBody>(string streamId)
        => ManagementResult<TBody>.NotFound(
            $"No stream '{streamId}' exists for this receiver (SSF 1.0 Section 8.1).");
}
