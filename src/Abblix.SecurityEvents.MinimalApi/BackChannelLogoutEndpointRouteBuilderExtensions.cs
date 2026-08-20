// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.BackChannelLogout;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Net.Http.Headers;

namespace Abblix.SecurityEvents.MinimalApi;

/// <summary>
/// Maps the back-channel logout intake onto a route.
/// </summary>
public static class BackChannelLogoutEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the endpoint a provider POSTs Logout Tokens to
    /// (OpenID Connect Back-Channel Logout 1.0 Section 2.5).
    /// </summary>
    /// <remarks>
    /// The route is the one the client registered as its <c>backchannel_logout_uri</c>, so the
    /// pattern is the host's to choose and this makes no assumption about it.
    /// </remarks>
    /// <param name="endpoints">The route builder.</param>
    /// <param name="pattern">The route registered as this client's back-channel logout URI.</param>
    public static IEndpointConventionBuilder MapBackChannelLogoutEndpoint(
        this IEndpointRouteBuilder endpoints,
        string pattern)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return endpoints.MapPost(pattern, HandleAsync);
    }

    /// <summary>
    /// Reads the request and renders what the handler decided.
    /// </summary>
    /// <remarks>
    /// Everything the specification says about the request and the answer lives in the handler, so
    /// this is transport and nothing else: the body as text, the status back, and the one header
    /// Section 2.8 asks for.
    /// </remarks>
    private static async Task<IResult> HandleAsync(
        HttpRequest request,
        BackChannelLogoutHandler handler,
        CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(request.Body);
        var body = await reader.ReadToEndAsync(cancellationToken);

        var result = await handler.HandleAsync(request.ContentType, body, cancellationToken);

        var httpResult = result switch
        {
            { Error: {} error, StatusCode: var statusCode } => Results.Json(error, statusCode: (int)statusCode),
            { StatusCode: var statusCode } => Results.StatusCode((int)statusCode),
        };

        // "The RP's response SHOULD include the Cache-Control HTTP response header field with a
        // no-store value" (Section 2.8). Set on the refusal as well as the success: a cached 400
        // would keep answering for a token that was only invalid the first time, which is exactly
        // the interference the header exists to prevent.
        return httpResult.WithHeaders(
            headers => headers.CacheControl = CacheControlHeaderValue.NoStoreString);
    }
}
