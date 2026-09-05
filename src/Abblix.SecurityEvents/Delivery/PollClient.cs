// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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

        using var message = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = JsonContent.Create(request),
        };

        // "When the SET Recipient includes one or more error responses in a request to the SET
        // Transmitter, it must also include in the request a 'Content-Language' header field whose
        // value indicates the language of the error descriptions included in the request"
        // (RFC 8936 Section 2.6). Only then: a poll that reports nothing carries no descriptions
        // for the header to describe.
        if (request.Errors is { Count: > 0 })
            message.Content.Headers.ContentLanguage.Add(PushDeliveryResult.ErrorLanguage);

        using var response = await httpClient.SendAsync(message, cancellationToken);
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
