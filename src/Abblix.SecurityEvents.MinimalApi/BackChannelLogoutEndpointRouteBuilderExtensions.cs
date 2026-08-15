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
        return new NoStore(httpResult);
    }

    /// <summary>
    /// Writes the one header Section 2.8 asks for, then renders what the handler decided.
    /// </summary>
    /// <remarks>
    /// A wrapper rather than a line touching the response before the result is returned, so the
    /// header cannot be attached to one answer and forgotten on the other: both answers travel
    /// through here by construction.
    /// </remarks>
    /// <param name="inner">The answer being rendered.</param>
    private sealed class NoStore(IResult inner) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            ArgumentNullException.ThrowIfNull(httpContext);

            httpContext.Response.Headers.CacheControl = CacheControlHeaderValue.NoStoreString;
            return inner.ExecuteAsync(httpContext);
        }
    }
}
