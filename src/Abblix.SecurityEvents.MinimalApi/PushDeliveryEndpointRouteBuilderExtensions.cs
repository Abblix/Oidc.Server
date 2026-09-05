// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Delivery;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Abblix.SecurityEvents.MinimalApi;

/// <summary>
/// Maps the push delivery intake onto a route.
/// </summary>
public static class PushDeliveryEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the endpoint a transmitter POSTs Security Event Tokens to (RFC 8935), answering the
    /// empty 202 or the 400 whose body speaks the registry vocabulary.
    /// </summary>
    /// <remarks>
    /// The route is the one the receiver advertised as its delivery endpoint, so the pattern is
    /// the host's to choose and this makes no assumption about it. Nothing here knows which
    /// profile of SET arrives: the handler is built by whichever consumer registered it, and
    /// carries that consumer's validation profile and sink.
    /// </remarks>
    /// <param name="endpoints">The route builder.</param>
    /// <param name="pattern">The route the receiver advertised as its push endpoint URL.</param>
    public static IEndpointConventionBuilder MapPushDeliveryEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return endpoints.MapPost(pattern, HandleAsync);
    }

    /// <summary>
    /// Reads the transmission and renders what the handler decided.
    /// </summary>
    private static async Task<IResult> HandleAsync(
        HttpRequest request,
        PushDeliveryHandler handler,
        CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(request.Body);
        var body = await reader.ReadToEndAsync(cancellationToken);

        var result = await handler.HandleAsync(request.ContentType, body, cancellationToken);
        if (result.Error is not { } error)
            return Results.StatusCode((int)result.StatusCode);

        // "The response MUST include a 'Content-Language' header field whose value indicates the
        // language of the error descriptions included in the response body" (RFC 8935 Section 2.3).
        return Results.Json(error, statusCode: (int)result.StatusCode)
            .WithHeaders(headers => headers.ContentLanguage = PushDeliveryResult.ErrorLanguage);
    }
}
