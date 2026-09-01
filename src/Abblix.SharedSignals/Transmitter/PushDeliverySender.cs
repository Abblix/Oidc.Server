// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text;
using System.Text.Json;
using Abblix.SecurityEvents.Delivery;
using Microsoft.Extensions.Logging;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// One delivery pass of a stream's outbox over push (RFC 8935, carried by SSF 1.0
/// Section 6.1.1): each pending SET is POSTed to the receiver's endpoint in enqueue order, an
/// accepted one is acknowledged out of the queue, and the pass stops at the first transient
/// failure so order survives into the next pass - which is also where retry lives: the caller's
/// schedule IS the backoff, and this type stays a single honest attempt.
/// </summary>
/// <param name="httpClient">The client transmissions travel through.</param>
/// <param name="outbox">The queues being drained.</param>
/// <param name="addressPolicy">Judges the receiver's address before anything is sent to it.</param>
/// <param name="logger">Carries the receiver's own reason for a refusal into this deployment's log.</param>
public sealed partial class PushDeliverySender(
    HttpClient httpClient,
    IEventOutbox outbox,
    ReceiverAddressPolicy addressPolicy,
    ILogger<PushDeliverySender> logger)
{
    /// <summary>How much of the receiver's description is carried into the log.</summary>
    /// <remarks>
    /// The field is the receiver's to fill and RFC 8935 Section 2.3 puts no bound on it - "the exact content
    /// of this field is implementation specific" - so it arrives as text of any length from a party this
    /// deployment does not control. A diagnostic that does not fit in this much is not a diagnostic.
    /// </remarks>
    private const int DescriptionBudget = 256;

    /// <summary>Stands in for a receiver that answered 400 without the error body it owes.</summary>
    /// <remarks>
    /// A code rather than a sentence, because the code is the field a log query groups by: a bucket named
    /// with prose sits beside invalid_audience and access_denied and cannot be told from one of them.
    /// </remarks>
    private static readonly DeliveryError Unexplained = new("(none)", string.Empty);

    /// <summary>The receiver's own words, bounded and stripped of anything that could forge a log line.</summary>
    /// <remarks>
    /// Control characters go first. A plain-text sink writes a newline as a newline, so a receiver could
    /// otherwise put a whole fabricated entry into this deployment's log through a field it fills itself -
    /// and the escapes that clear a terminal or rewrite its title ride the same path.
    /// </remarks>
    private static string Readable(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            return "(none)";
        }

        var kept = description.Length <= DescriptionBudget ? description : description[..DescriptionBudget];
        var text = new string([.. kept.Select(character => char.IsControl(character) ? ' ' : character)]);
        return description.Length <= DescriptionBudget ? text : text + "...";
    }

    /// <summary>
    /// Sends what one stream has pending.
    /// </summary>
    /// <remarks>
    /// A stream that is not enabled sends nothing except status announcements - holding is the
    /// pause's meaning (SSF 1.0 Section 8.1.2.1), and the announcement is the one item that
    /// must still go out, since Section 8.1.5 wants it with the receiver although the stop has
    /// already happened here.
    /// <para>
    /// A "400 Bad Request" carries the receiver's verdict in its body (RFC 8935 Section 2.3), and the verdict
    /// rather than the status decides what happens to the event. RFC 8935 Section 4 separates the two cases:
    /// a structural complaint "is likely to remain when retransmitting the same SET", so the event is dropped
    /// instead of poisoning the head of the queue, while a complaint about the transmitter's credentials or
    /// authorization "may be transient" and the event stays queued for a pass made after the deployment fixes
    /// what the receiver objected to.
    /// </para>
    /// </remarks>
    /// <param name="stream">The stream whose queue is drained.</param>
    /// <param name="cancellationToken">Cancels the pass between transmissions.</param>
    /// <returns>How the pass went: what was delivered, what the receiver rejected.</returns>
    public async Task<PushDeliveryPassOutcome> SendPendingAsync(
        StreamState stream,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (stream.Configuration.Delivery is not PushDeliveryMethod push)
        {
            return new PushDeliveryPassOutcome(0, 0);
        }

        // The receiver chose this address, so it is judged before anything is sent and on every pass: a name that
        // was public when the stream was created can resolve inside the network by the time an event is delivered.
        // A refusal holds the queue rather than emptying it, because the events are still owed to a receiver whose
        // configuration an operator can put right.
        if (await addressPolicy.RejectionOf(push.EndpointUrl, cancellationToken) is { } rejection)
        {
            throw new InvalidOperationException(
                $"Refusing to deliver stream '{stream.StreamId}' to '{push.EndpointUrl}': {rejection}.");
        }

        IEnumerable<OutboxItem> pending = await outbox.PendingAsync(
            stream.ReceiverId, stream.StreamId, null, cancellationToken);
        if (stream.Status != StreamStatuses.Enabled)
        {
            pending = pending.Where(item => item.IsStatusAnnouncement);
        }

        var delivered = 0;
        var rejected = 0;

        // The first refusal of the pass, kept so the summary below can name a reason. Per-SET logging
        // is what the queue's own shape rules out: it is read whole, so a receiver that refuses a
        // backlog would write one line per event - thousands in one pass, differing only in the
        // identifier, which is the drowning this line exists to prevent rather than cause.
        DeliveryError? firstRefusal = null;
        foreach (var item in pending)
        {
            HttpResponseMessage response;
            try
            {
                response = await SendAsync(push, item, cancellationToken);
            }
            catch (HttpRequestException)
            {
                // The transport failed before the receiver answered: transient by definition,
                // so the pass ends and the item waits for the next one, order intact.
                break;
            }

            using (response)
            {
                if (response.StatusCode == HttpStatusCode.BadRequest)
                {
                    var verdict = await ReadVerdictAsync(response, cancellationToken);
                    if (!DeliveryErrorCodes.IsFinal(verdict?.Error))
                    {
                        // The receiver objects to this transmitter, not to this event: leave it queued so a
                        // later pass can deliver it once the credentials or the grant are put right.
                        // Non-null by construction: IsFinal answers false only for a code it recognises.
                        LogReceiverObjected(stream.StreamId, verdict!.Error, Readable(verdict.Description));
                        break;
                    }

                    firstRefusal ??= verdict ?? Unexplained;

                    await outbox.AcknowledgeAsync(
                        stream.ReceiverId, stream.StreamId, [item.JwtId], cancellationToken);
                    rejected++;
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    break;
                }

                await outbox.AcknowledgeAsync(
                    stream.ReceiverId, stream.StreamId, [item.JwtId], cancellationToken);
                delivered++;
            }
        }

        // Once for the pass, naming the count and the first reason. The receiver owes a reason with a
        // 400 (RFC 8935 Section 2.3) and it is read here to decide whether a retransmission could ever
        // succeed; nothing else carries it onward, so without this the only thing this side holds about
        // a stream refusing everything is a number that looks like a stream refusing nothing.
        if (rejected > 0)
        {
            LogSetsRefused(
                stream.StreamId, rejected, firstRefusal!.Error, Readable(firstRefusal.Description));
        }

        return new PushDeliveryPassOutcome(delivered, rejected);
    }

    /// <summary>
    /// Reads the error body a receiver owes with a 400 (RFC 8935 Section 2.3).
    /// </summary>
    /// <remarks>
    /// A body that is missing, malformed or of another media type yields null, which the caller treats as final.
    /// The alternative, treating an unreadable verdict as transient, would let a receiver answering 400 with an
    /// HTML error page hold the head of the queue for as long as it kept doing so.
    /// </remarks>
    private static async Task<DeliveryError?> ReadVerdictAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<DeliveryError>(cancellationToken);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or HttpRequestException)
        {
            return null;
        }
    }

    private async Task<HttpResponseMessage> SendAsync(
        PushDeliveryMethod push,
        OutboxItem item,
        CancellationToken cancellationToken)
    {
        // "POST ... with a media type of 'application/secevent+jwt'" and a JSON error body to
        // accept back (RFC 8935 Sections 2.1-2.3).
        using var request = new HttpRequestMessage(HttpMethod.Post, push.EndpointUrl)
        {
            Content = new StringContent(
                item.CompactToken, Encoding.UTF8, SecurityEventTokenMediaTypes.SecurityEventToken),
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Json));

        // "If present, the Transmitter MUST provide this value with every HTTP request to the
        // endpoint_url" (SSF 1.0 Section 6.1.1). The value is the receiver's whole header line,
        // taken as given.
        if (push.AuthorizationHeader is { } authorization)
        {
            request.Headers.TryAddWithoutValidation(
                nameof(HttpRequestHeader.Authorization), authorization);
        }

        return await httpClient.SendAsync(request, cancellationToken);
    }
}