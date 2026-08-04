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
using System.Net.Mime;
using System.Text;
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
public sealed class PushDeliverySender(HttpClient httpClient, IEventOutbox outbox)
{
    /// <summary>
    /// Sends what one stream has pending.
    /// </summary>
    /// <remarks>
    /// A stream that is not enabled sends nothing except status announcements - holding is the
    /// pause's meaning (SSF 1.0 Section 8.1.2.1), and the announcement is the one item that
    /// must still go out, since Section 8.1.5 wants it with the receiver although the stop has
    /// already happened here. A "400 Bad Request" is the receiver's terminal judgment of that
    /// SET (RFC 8935 Section 2.3): retrying the same bytes cannot succeed and would poison the
    /// head of the queue, so the item is dropped and counted rejected.
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
