// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;

using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Fans one security event out to the streams it belongs on: for every stream it checks the
/// status, the delivered event types, the subject coverage (SSF 1.0 Section 8.1.3.1) and -
/// last - the sharing policy (Section 9.2), then mints a per-stream SET and hands it to the
/// stream's outbox. Delivery itself is someone else's clock: a sender drains the outbox for
/// enabled streams, and a paused stream's events simply wait.
/// </summary>
/// <param name="streams">The transmitter's streams.</param>
/// <param name="outbox">Where minted SETs wait for delivery.</param>
/// <param name="signer">Signs each minted SET.</param>
/// <param name="issuer">
/// The transmitter's issuer identifier - the "iss" of every SET, identical to the issuer the
/// configuration metadata asserts (SSF 1.0 Section 7.1).</param>
/// <param name="sharingPolicy">
/// The host's Section 9.2 verdict; null shares every otherwise-matching event, which is the
/// honest default only for a transmitter whose events carry nothing the receiver may not see.
/// </param>
/// <param name="clock">Supplies "iat"; null takes the system clock.</param>
/// <param name="logger">Records the streams a fan-out could not reach.</param>
/// <param name="payloadPolicy">
/// What this deployment refuses to emit, over and above what the event vocabulary permits - how a
/// deployment claims a profile such as the CAEP Interoperability Profile. Null emits whatever the host
/// builds, which is what a transmitter claiming no profile does.
/// </param>
public sealed partial class EventDispatcher(
    ILogger<EventDispatcher> logger,
    IStreamStore streams,
    IEventOutbox outbox,
    ISecurityEventTokenSigner signer,
    string issuer,
    IEventSharingPolicy? sharingPolicy = null,
    IEventPayloadPolicy? payloadPolicy = null,
    TimeProvider? clock = null)
{
    private readonly string _issuer = !string.IsNullOrEmpty(issuer)
        ? issuer
        : throw new ArgumentException("A transmitter without an issuer identifier can sign nothing.", nameof(issuer));

    /// <summary>
    /// Dispatches one event to every stream it matches.
    /// </summary>
    /// <param name="descriptor">The event as the application states it.</param>
    /// <param name="cancellationToken">Cancels store reads, policy calls and signing.</param>
    /// <returns>How many streams the event was enqueued for - zero is a legitimate answer for
    /// an event nobody subscribed to.</returns>
    public async Task<int> DispatchAsync(
        SecurityEventDescriptor descriptor,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        RefuseIfOutsidePolicy(descriptor);

        var reached = 0;
        foreach (var stream in await streams.ListAllAsync(cancellationToken))
        {
            // A disabled stream holds nothing (Section 8.1.2.1); a paused one is enqueued for -
            // holding events IS the outbox waiting, and same-principal order is enqueue order.
            if (stream.Status == StreamStatuses.Disabled)
            {
                continue;
            }

            if (stream.Configuration.EventsDelivered is not { } delivered
                || !delivered.Contains(descriptor.EventType, StringComparer.Ordinal))
            {
                continue;
            }

            if (!CoversSubject(stream, descriptor.Subject))
            {
                continue;
            }

            // The sharing policy runs last, so it is consulted only about deliveries that would
            // otherwise happen - its cost and its logs both scale with reality.
            if (sharingPolicy is not null
                && !await sharingPolicy.IsSharingPermittedAsync(stream, descriptor, cancellationToken))
            {
                continue;
            }

            // One stream's failure is one stream's. Letting it out of the loop would drop the
            // fan-out to every stream after it AND lose the count with the exception, so a caller
            // would learn neither who received the event nor that anybody had.
            try
            {
                await MintAndEnqueueAsync(stream, descriptor, asStatusAnnouncement: false, cancellationToken);
                reached++;
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                LogStreamNotReached(exception, stream.StreamId, descriptor.EventType);
            }
        }

        return reached;
    }

    /// <summary>
    /// Dispatches one event to one stream, skipping the matching checks: the door for the
    /// framework's own signals, which a transmitter may send "even if the event is not present
    /// in the events_supported, events_requested and / or events_delivered fields"
    /// (SSF 1.0 Sections 8.1.4, 8.1.5) - and which must go out even to a stream being paused
    /// or disabled, since the stream-updated event precedes the stop.
    /// </summary>
    /// <param name="stream">The stream the event targets.</param>
    /// <param name="descriptor">The event; for verification and stream-updated its subject is
    /// the stream's own opaque identifier (SSF 1.0 Sections 8.1.4.1, 8.1.5).</param>
    /// <param name="asStatusAnnouncement">
    /// True for the stream-updated event escorting a transmitter-initiated status change, so
    /// delivery carries it even over the stream it stops (SSF 1.0 Section 8.1.5).</param>
    /// <param name="cancellationToken">Cancels signing and the enqueue.</param>
    public Task DispatchToStreamAsync(
        StreamState stream,
        SecurityEventDescriptor descriptor,
        bool asStatusAnnouncement = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(descriptor);

        // Deliberately unjudged. This door carries the framework's OWN signals - verification and
        // stream-updated - minted by this library from payloads a host never built, and reached through a
        // receiver's request: a refusal here would fire after the throttle or the status has already been
        // written, turning a receiver's verification request into a fault mid-operation and breaking the
        // very profile a policy was registered to claim. A policy is about what the HOST asks this
        // transmitter to emit, and that is DispatchAsync.
        return MintAndEnqueueAsync(stream, descriptor, asStatusAnnouncement, cancellationToken);
    }

    /// <summary>
    /// Refuses an event this deployment has undertaken not to emit, before anything is minted.
    /// </summary>
    /// <remarks>
    /// Asked once per event rather than once per stream: the payload is identical for every receiver, so a
    /// per-stream answer would emit to some and withhold from others by iteration order. Asked on this
    /// entry point alone - <see cref="DispatchToStreamAsync"/> says why it is not.
    /// <para>
    /// It throws rather than dropping the event with a log line, and the choice is not a preference. A
    /// dropped <c>session-revoked</c> is a revocation that never happens, which is a worse outcome than a
    /// non-conformant event; and on this path the caller is the application code that built the payload,
    /// so the throw reaches whoever can fix it. Nothing throws unless the host registered a policy.
    /// </para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">The policy refused the event.</exception>
    private void RefuseIfOutsidePolicy(SecurityEventDescriptor descriptor)
    {
        if (payloadPolicy?.RefusalOf(descriptor.EventType, descriptor.Payload) is { } refusal)
        {
            throw new InvalidOperationException(refusal);
        }
    }

    /// <summary>
    /// Whether the stream's subject bookkeeping covers the subject, per the wildcard matching
    /// of Section 8.1.3.1 over the mode of Section 7.1: under ALL everything is covered except
    /// what was removed, with a later re-addition winning over the removal; under NONE only
    /// what was added is covered.
    /// </summary>
    private static bool CoversSubject(StreamState stream, SubjectIdentifier subject)
        => stream.SubjectsMode switch
        {
            StreamSubjectsMode.All =>
                stream.AddedSubjects.Any(added => SubjectMatcher.Matches(added.Subject, subject))
                || !stream.RemovedSubjects.Any(removed => SubjectMatcher.Matches(removed, subject)),
            StreamSubjectsMode.None =>
                stream.AddedSubjects.Any(added => SubjectMatcher.Matches(added.Subject, subject)),
            _ => throw new InvalidOperationException(
                $"Unknown {nameof(StreamSubjectsMode)}: {stream.SubjectsMode}."),
        };

    private async Task MintAndEnqueueAsync(
        StreamState stream,
        SecurityEventDescriptor descriptor,
        bool asStatusAnnouncement,
        CancellationToken cancellationToken)
    {
        // Each stream gets its own SET: its own identifier, its own audience. Sharing one token
        // across receivers is exactly the unintended-disclosure shape Section 4.1.8 warns about.
        var jwtId = Guid.NewGuid().ToString("N");

        // Declared rather than merely true, and no test can hold it: a descriptor carries one event type,
        // a single required string, so nothing here can add a second statement and the constraint has no
        // input that makes it speak. What it buys is the day somebody widens this method - the widening
        // fails here instead of reaching a receiver as a SET the CAEP Interoperability Profile forbids,
        // whose Section 2.8.1 requires the "events" claim to contain only one event. The same reasoning
        // as the unreachable arm in StreamManagementService.AddressRefusalOf, and said out loud for the
        // same reason: an unreachable guard nobody explained reads as one nobody finished.
        var builder = new SecurityEventTokenBuilder(clock) { SingleEventStatement = true }
            .WithIssuer(_issuer)
            .WithJwtId(jwtId)
            .WithAudience([.. stream.Configuration.Audiences])
            .WithSubjectId(descriptor.Subject);

        if (descriptor.TransactionId is { } transactionId)
        {
            builder.WithTransactionId(transactionId);
        }

        if (descriptor.TimeOfEvent is { } timeOfEvent)
        {
            builder.WithTimeOfEvent(timeOfEvent);
        }

        if (descriptor.Payload is { } payload)
        {
            builder.WithEvent(descriptor.EventType, payload);
        }
        else
        {
            builder.WithEvent(descriptor.EventType);
        }

        var compactToken = await builder.SignAsync(signer, cancellationToken);
        await outbox.EnqueueAsync(
            stream.StreamId,
            new OutboxItem(jwtId, compactToken, asStatusAnnouncement),
            cancellationToken);
    }
}
