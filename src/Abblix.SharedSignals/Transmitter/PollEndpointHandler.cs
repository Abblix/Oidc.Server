// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The transmitter's half of one poll exchange (RFC 8936, carried by SSF 1.0 Section 6.1.2):
/// release what the receiver acknowledged, then answer with what waits. A host adapter owns
/// routing, authentication and any long-poll waiting; this type answers from the queue as it
/// is.
/// </summary>
/// <param name="logger">Records an event this side could not serve.</param>
/// <param name="outbox">The queues being served.</param>
/// <param name="signer">Signs each SET as it is served, so a receiver that polls late still accepts its issue
/// time.</param>
public sealed partial class PollEndpointHandler(
    ILogger<PollEndpointHandler> logger,
    IEventOutbox outbox,
    QueuedEventSigner signer)
{
    /// <summary>
    /// Handles one poll request for one stream.
    /// </summary>
    /// <remarks>
    /// An acknowledgement releases retention, and only an acknowledgement does: RFC 8936
    /// Section 2.2 says of "ack" that "the SET Transmitter is released from any obligation to
    /// retain the SET", and says no such thing of "setErrs". An error report is released only when
    /// the code says redelivery cannot change the answer - the same reading the push sender
    /// applies, so one registry does not decide two ways in one package. A receiver whose
    /// credentials lapsed reports "access_denied" and keeps its events. A stream that
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
            released.AddRange(
                errors.Where(reported => DeliveryErrorCodes.IsFinal(reported.Value?.Error))
                    .Select(reported => reported.Key));
        }

        if (released.Count > 0)
        {
            await outbox.AcknowledgeAsync(
                stream.ReceiverId, stream.StreamId, released, cancellationToken);
        }

        // Zero asks for nothing: the acknowledge-only poll (RFC 8936 Section 2.2). The "sets"
        // object still travels, empty - it is never absent (Section 2.3). A negative value asks
        // for nothing either, and is answered the same way rather than falling through: Take with
        // a negative count yields nothing while the "moreAvailable" below still reports a queue,
        // and a receiver reading that answer polls again forever with no way to see why.
        if (request.MaxEvents is <= 0)
        {
            return new PollResponse();
        }

        IReadOnlyList<OutboxItem> pending =
            await outbox.PendingAsync(stream.ReceiverId, stream.StreamId, null, cancellationToken);
        if (stream.Status != StreamStatuses.Enabled)
        {
            pending = [.. pending.Where(item => item.IsStatusAnnouncement)];
        }

        var page = request.MaxEvents is { } maxEvents ? [.. pending.Take(maxEvents)] : pending;

        return new PollResponse
        {
            Sets = await SignAsync(stream, page, cancellationToken),
            // Omitted means false (RFC 8936 Section 2.3), so false stays off the wire.
            MoreAvailable = pending.Count > page.Count ? true : null,
        };
    }

    /// <summary>
    /// The page's SETs, each signed now. An item holding neither a token nor an unsigned form is dropped from the
    /// queue rather than served, since kept it would fail every poll after this one.
    /// </summary>
    private async Task<Dictionary<string, string>> SignAsync(
        StreamState stream,
        IReadOnlyList<OutboxItem> page,
        CancellationToken cancellationToken)
    {
        var sets = new Dictionary<string, string>(StringComparer.Ordinal);
        var unsendable = new List<string>();
        foreach (var item in page)
        {
            string? token;
            try
            {
                token = await signer.SignAsync(item, cancellationToken);
            }
            catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
            {
                LogSigningFailed(exception, stream.StreamId, item.JwtId);
                throw;
            }

            if (token is null)
            {
                LogUnsendableItemDropped(stream.StreamId, item.JwtId);
                unsendable.Add(item.JwtId);
                continue;
            }

            sets.Add(item.JwtId, token);
        }

        if (unsendable.Count > 0)
        {
            await outbox.AcknowledgeAsync(stream.ReceiverId, stream.StreamId, unsendable, cancellationToken);
        }

        return sets;
    }
}
