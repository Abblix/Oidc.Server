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

using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The transmitter's half of one poll exchange (RFC 8936, carried by SSF 1.0 Section 6.1.2):
/// release what the receiver acknowledged, then answer with what waits. A host adapter owns
/// routing, authentication and any long-poll waiting; this type answers from the queue as it
/// is.
/// </summary>
/// <param name="outbox">The queues being served.</param>
public sealed class PollEndpointHandler(IEventOutbox outbox)
{
    /// <summary>
    /// Handles one poll request for one stream.
    /// </summary>
    /// <remarks>
    /// Acknowledged and error-reported SETs alike are released from retention: the
    /// acknowledgement says delivery succeeded, the error report is the receiver's terminal
    /// judgment, and redelivering either would be noise (RFC 8936 Section 2.2). A stream that
    /// is not enabled serves nothing except status announcements - the pause holds events
    /// (SSF 1.0 Section 8.1.2.1), and the announcement is what Section 8.1.5 still owes the
    /// receiver after the stop.
    /// </remarks>
    /// <param name="stream">The stream being polled.</param>
    /// <param name="request">What the receiver acknowledges and asks for.</param>
    /// <param name="cancellationToken">Cancels outbox I/O.</param>
    public async Task<PollResponse> HandleAsync(
        StreamState stream,
        PollRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(request);

        var released = new List<string>(request.Acknowledged ?? []);
        if (request.Errors is { Count: > 0 } errors)
        {
            released.AddRange(errors.Keys);
        }

        if (released.Count > 0)
        {
            await outbox.AcknowledgeAsync(stream.StreamId, released, cancellationToken);
        }

        // Zero asks for nothing: the acknowledge-only poll (RFC 8936 Section 2.2). The "sets"
        // object still travels, empty - it is never absent (Section 2.3).
        if (request.MaxEvents is 0)
        {
            return new PollResponse();
        }

        IReadOnlyList<OutboxItem> pending =
            await outbox.PendingAsync(stream.StreamId, null, cancellationToken);
        if (stream.Status != StreamStatuses.Enabled)
        {
            pending = [.. pending.Where(item => item.IsStatusAnnouncement)];
        }

        IEnumerable<OutboxItem> page = pending;
        if (request.MaxEvents is { } maxEvents)
        {
            page = page.Take(maxEvents);
        }

        var sets = page.ToDictionary(item => item.JwtId, item => item.CompactToken, StringComparer.Ordinal);

        return new PollResponse
        {
            Sets = sets,
            // Omitted means false (RFC 8936 Section 2.3), so false stays off the wire.
            MoreAvailable = pending.Count > sets.Count ? true : null,
        };
    }
}
