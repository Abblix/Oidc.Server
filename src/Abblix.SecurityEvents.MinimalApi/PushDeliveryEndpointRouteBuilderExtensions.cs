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
