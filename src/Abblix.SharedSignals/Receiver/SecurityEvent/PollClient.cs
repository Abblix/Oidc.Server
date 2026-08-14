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

using System.Net.Http.Json;
using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// The receiver's side of poll-based delivery (RFC 8936, carried by SSF 1.0 Section 6.1.2): one
/// POST that acknowledges what was processed and asks for what waits. The wire shapes live in
/// the Security Events core; this type owns only the transport.
/// </summary>
/// <param name="httpClient">The client polls are spoken through. Authentication is its
/// configuration, not this type's concern.</param>
public sealed class PollClient(HttpClient httpClient)
{
    /// <summary>
    /// Polls the endpoint of a stream's poll delivery for pending Security Event Tokens.
    /// </summary>
    /// <param name="delivery">The stream's poll delivery, whose endpoint URL the transmitter
    /// supplied at stream creation (SSF 1.0 Sections 6.1.2, 8.1.1.1).</param>
    /// <param name="request">What to acknowledge and what to return; the empty request is a
    /// valid default poll (RFC 8936 Section 2.2).</param>
    /// <param name="cancellationToken">Cancels the poll - the way a caller bounds a long poll
    /// the transmitter holds open.</param>
    public Task<PollResponse> PollAsync(
        PollDeliveryMethod delivery,
        PollRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(delivery);

        // A delivery without the URL is a receiver's own PROPOSAL of poll, not a pollable
        // stream: the URL is transmitter-supplied, so only the configuration the transmitter
        // returned carries it (SSF 1.0 Sections 6.1.2, 8.1.1.1).
        if (delivery.EndpointUrl is not { } endpoint)
        {
            throw new InvalidOperationException(
                $"The poll delivery carries no '{StreamDeliveryMethod.ParameterNames.EndpointUrl}': poll "
                + "the delivery of a transmitter-returned stream configuration, not a receiver-side "
                + "proposal (SSF 1.0 Sections 6.1.2, 8.1.1.1).");
        }

        return PollAsync(endpoint, request, cancellationToken);
    }

    /// <summary>
    /// Polls <paramref name="endpoint"/> for pending Security Event Tokens.
    /// </summary>
    /// <param name="endpoint">The transmitter-supplied poll endpoint URL.</param>
    /// <param name="request">What to acknowledge and what to return.</param>
    /// <param name="cancellationToken">Cancels the poll.</param>
    /// <exception cref="HttpRequestException">The transmitter answered with an error status.
    /// </exception>
    public async Task<PollResponse> PollAsync(
        Uri endpoint,
        PollRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(request);

        using var response = await httpClient.PostAsJsonAsync(endpoint, request, cancellationToken);
        response.EnsureSuccessStatusCode();

        var pollResponse = await response.Content.ReadFromJsonAsync<PollResponse>(cancellationToken);
        if (pollResponse == null)
        {
            throw new InvalidOperationException(
                "The poll response deserialized to null; a transmitter with nothing to deliver "
                + "answers with an empty \"sets\" object (RFC 8936 Section 2.3).");
        }

        return pollResponse;
    }
}
