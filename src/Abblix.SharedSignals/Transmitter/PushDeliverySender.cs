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
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text;
using System.Text.Json;
using Abblix.SecurityEvents.Delivery;
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
public sealed class PushDeliverySender(
    HttpClient httpClient,
    IEventOutbox outbox,
    ReceiverAddressPolicy addressPolicy)
{
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

        IEnumerable<OutboxItem> pending = await outbox.PendingAsync(stream.StreamId, null, cancellationToken);
        if (stream.Status != StreamStatuses.Enabled)
        {
            pending = pending.Where(item => item.IsStatusAnnouncement);
        }

        var delivered = 0;
        var rejected = 0;
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
                        break;
                    }

                    await outbox.AcknowledgeAsync(stream.StreamId, [item.JwtId], cancellationToken);
                    rejected++;
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    break;
                }

                await outbox.AcknowledgeAsync(stream.StreamId, [item.JwtId], cancellationToken);
                delivered++;
            }
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

/// <summary>
/// What one push delivery pass achieved.
/// </summary>
/// <param name="Delivered">SETs the receiver accepted and the queue released.</param>
/// <param name="Rejected">SETs the receiver judged invalid, dropped from the queue as terminal
/// (RFC 8935 Section 2.3).</param>
public sealed record PushDeliveryPassOutcome(int Delivered, int Rejected);
