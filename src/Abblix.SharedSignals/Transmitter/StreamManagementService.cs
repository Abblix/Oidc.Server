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

using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Events;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;

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
/// <param name="clock">Measures the verification throttle; null takes the system clock.</param>
public sealed class StreamManagementService(
    IStreamStore store,
    IEventOutbox outbox,
    EventDispatcher dispatcher,
    SsfTransmitterOptions options,
    TimeProvider? clock = null)
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

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

        if (!options.AllowMultipleStreamsPerReceiver
            && (await store.ListAsync(receiverId, cancellationToken)).Count > 0)
        {
            return ManagementResult<StreamConfiguration>.Conflict(
                "The receiver already has a stream, and this transmitter allows one per receiver "
                + "(SSF 1.0 Section 8.1.1.1); read it and update or replace what differs.");
        }

        var streamId = Guid.NewGuid().ToString("N");

        if (ResolveDelivery(request.Delivery, streamId) is not { } delivery)
        {
            return ManagementResult<StreamConfiguration>.BadRequest(
                "The requested delivery method is not supported by this transmitter "
                + "(SSF 1.0 Section 8.1.1.1).");
        }

        var configuration = new StreamConfiguration
        {
            StreamId = streamId,
            Issuer = options.Issuer,
            Audiences = [.. options.AudiencesFactory?.Invoke(receiverId) ?? [receiverId]],
            EventsSupported = options.EventsSupported is { Count: > 0 } supported ? supported : null,
            EventsRequested = request.EventsRequested,
            EventsDelivered = DeliveredOf(request.EventsRequested),
            Delivery = delivery,
            MinVerificationInterval = options.MinVerificationInterval,
            Description = request.Description,
        };

        var created = new StreamState
        {
            ReceiverId = receiverId,
            Configuration = configuration,
            SubjectsMode = options.DefaultSubjectsMode,
        };

        return await store.TryCreateAsync(created, cancellationToken)
            ? ManagementResult<StreamConfiguration>.Created(configuration)
            : ManagementResult<StreamConfiguration>.Conflict(
                "A stream with the generated identifier already exists.");
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
            if (ResolveDelivery(proposedDelivery, stream.StreamId) is not { } delivery)
            {
                return ManagementResult<StreamConfiguration>.BadRequest(
                    "The requested delivery method is not supported by this transmitter.");
            }

            configuration = configuration with { Delivery = delivery };
        }

        if (request.EventsRequested is { } requested)
        {
            configuration = configuration with
            {
                EventsRequested = requested,
                EventsDelivered = DeliveredOf(requested),
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

        if (ResolveDelivery(request.Delivery, stream.StreamId) is not { } delivery)
        {
            return ManagementResult<StreamConfiguration>.BadRequest(
                "The requested delivery method is not supported by this transmitter.");
        }

        var configuration = stream.Configuration with
        {
            Delivery = delivery,
            EventsRequested = request.EventsRequested,
            EventsDelivered = DeliveredOf(request.EventsRequested),
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

        await outbox.ClearAsync(streamId, cancellationToken);
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

        if (await store.FindAsync(receiverId, request.StreamId, cancellationToken) is not { } stream)
        {
            return NoSuchStream<StreamStatus>(request.StreamId);
        }

        var updated = stream with { Status = request.Status, StatusReason = request.Reason };
        if (!await store.UpdateAsync(updated, cancellationToken))
        {
            return NoSuchStream<StreamStatus>(request.StreamId);
        }

        if (request.Status == StreamStatuses.Disabled)
        {
            await outbox.ClearAsync(stream.StreamId, cancellationToken);
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
        if (request.Subject is ComplexSubject { HasMembers: false })
        {
            return ManagementResult<object>.BadRequest(
                "A complex subject carries at least one member (SSF 1.0 Section 3.3); one with none "
                + "would match every event on the stream.");
        }

        if (await store.FindAsync(receiverId, request.StreamId, cancellationToken) is not { } stream)
        {
            return NoSuchStream<object>(request.StreamId);
        }

        var subject = new StreamSubject(request.Subject, request.Verified ?? true);

        var updated = stream with
        {
            AddedSubjects =
            [
                .. stream.AddedSubjects.Where(
                    added => !SubjectMatcher.Identical(added.Subject, request.Subject)),
                subject,
            ],
            // Under ALL, an addition undoes an earlier removal; under NONE the removal list is
            // inert, and dropping a stale entry there costs nothing.
            RemovedSubjects =
            [
                .. stream.RemovedSubjects.Where(
                    removed => !SubjectMatcher.Identical(removed, request.Subject)),
            ],
        };

        return await store.UpdateAsync(updated, cancellationToken)
            ? ManagementResult<object>.Ok()
            : NoSuchStream<object>(request.StreamId);
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

        if (await store.FindAsync(receiverId, request.StreamId, cancellationToken) is not { } stream)
        {
            return NoSuchStream<object>(request.StreamId);
        }

        var updated = stream with
        {
            AddedSubjects =
            [
                .. stream.AddedSubjects.Where(
                    added => !SubjectMatcher.Identical(added.Subject, request.Subject)),
            ],
            RemovedSubjects = stream.SubjectsMode switch
            {
                // Under ALL a removal carves the subject out of the default coverage.
                StreamSubjectsMode.All when !stream.RemovedSubjects.Any(
                        removed => SubjectMatcher.Identical(removed, request.Subject)) =>
                    [.. stream.RemovedSubjects, request.Subject],
                _ => stream.RemovedSubjects,
            },
        };

        return await store.UpdateAsync(updated, cancellationToken)
            ? ManagementResult<object>.NoContent()
            : NoSuchStream<object>(request.StreamId);
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

        await dispatcher.DispatchToStreamAsync(
            stream,
            new SecurityEventDescriptor
            {
                EventType = SsfEventTypes.Verification,
                // The stream's own subject: opaque, its id the stream's (Section 8.1.4.1).
                Subject = new OpaqueSubject(stream.StreamId),
                Payload = new VerificationEventPayload { State = request.State },
            },
            cancellationToken: cancellationToken);

        await store.UpdateAsync(stream with { LastVerificationRequestAt = now }, cancellationToken);
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

        if (status == StreamStatuses.Disabled)
        {
            // "will not hold any events" (Section 8.1.2.1) - and dropped before the
            // announcement is enqueued, so the announcement survives the drop.
            await outbox.ClearAsync(stream.StreamId, cancellationToken);
        }

        await dispatcher.DispatchToStreamAsync(
            stream,
            new SecurityEventDescriptor
            {
                EventType = SsfEventTypes.StreamUpdated,
                Subject = new OpaqueSubject(stream.StreamId),
                Payload = new StreamUpdatedEventPayload { Status = status, Reason = reason },
            },
            asStatusAnnouncement: true,
            cancellationToken);

        return await store.UpdateAsync(
            stream with { Status = status, StatusReason = reason },
            cancellationToken);
    }

    /// <summary>
    /// The receiver-visible delivery for a proposal: push keeps the receiver's endpoint, poll
    /// gets this transmitter's own URL - the "endpoint_url value is supplied by the
    /// Transmitter" (SSF 1.0 Section 8.1.1.1) - and an absent proposal means poll. Null when
    /// the transmitter cannot serve the method.
    /// </summary>
    private StreamDeliveryMethod? ResolveDelivery(StreamDeliveryMethod? proposed, string streamId)
        => proposed switch
        {
            PushDeliveryMethod push => push,
            PollDeliveryMethod or null when options.PollEndpointFactory is { } pollEndpointOf =>
                new PollDeliveryMethod(pollEndpointOf(streamId)),
            _ => null,
        };

    /// <summary>
    /// "events_delivered" as SSF 1.0 Section 8.1.1 defines it: a subset of the intersection of
    /// supported and requested, kept in the receiver's request order.
    /// </summary>
    private IReadOnlyList<string> DeliveredOf(IReadOnlyList<string>? requested)
        => requested is null
            ? []
            : [.. requested.Where(eventType => options.EventsSupported.Contains(eventType, StringComparer.Ordinal))];

    private async Task<ManagementResult<StreamConfiguration>> SaveConfigurationAsync(
        StreamState stream,
        StreamConfiguration configuration,
        CancellationToken cancellationToken)
        => await store.UpdateAsync(stream with { Configuration = configuration }, cancellationToken)
            ? ManagementResult<StreamConfiguration>.Ok(configuration)
            : NoSuchStream<StreamConfiguration>(stream.StreamId);

    private static StreamStatus StatusOf(StreamState stream) => new()
    {
        StreamId = stream.StreamId,
        Status = stream.Status,
        Reason = stream.StatusReason,
    };

    private static ManagementResult<TBody> NoSuchStream<TBody>(string streamId)
        => ManagementResult<TBody>.NotFound(
            $"No stream '{streamId}' exists for this receiver (SSF 1.0 Section 8.1).");
}
