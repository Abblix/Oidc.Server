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

namespace Abblix.SecurityEvents.Delivery;

/// <summary>
/// The receiver's side of poll-based delivery (RFC 8936): one POST that acknowledges what was
/// processed and asks for what waits. The wire shapes live beside it; this type owns only the
/// transport.
/// </summary>
/// <remarks>
/// It knows nothing of how the endpoint was learned. RFC 8936 leaves that to whatever arranged
/// the feed, so a framework that carries poll deliveries in its own configuration - Shared
/// Signals does - adds the step from its model to this URL on its own side.
/// </remarks>
/// <param name="httpClient">The client polls are spoken through. Authentication is its
/// configuration, not this type's concern.</param>
public sealed class PollClient(HttpClient httpClient)
{
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
