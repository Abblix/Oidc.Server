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
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// Polls a stream by its delivery configuration rather than by a bare URL.
/// </summary>
/// <remarks>
/// The step from a Shared Signals stream to the endpoint RFC 8936 speaks to. It stays on this
/// side because the delivery model is this framework's: the poll client below knows a URL, and
/// which URL a stream has is a question only a stream configuration answers.
/// </remarks>
public static class PollClientExtensions
{
    /// <summary>
    /// Polls the endpoint of a stream's poll delivery for pending Security Event Tokens.
    /// </summary>
    /// <param name="client">The transport.</param>
    /// <param name="delivery">The stream's poll delivery, whose endpoint URL the transmitter
    /// supplied at stream creation (SSF 1.0 Sections 6.1.2, 8.1.1.1).</param>
    /// <param name="request">What to acknowledge and what to return; the empty request is a
    /// valid default poll (RFC 8936 Section 2.2).</param>
    /// <param name="cancellationToken">Cancels the poll - the way a caller bounds a long poll
    /// the transmitter holds open.</param>
    public static Task<PollResponse> PollAsync(
        this PollClient client,
        PollDeliveryMethod delivery,
        PollRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
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

        return client.PollAsync(endpoint, request, cancellationToken);
    }
}
