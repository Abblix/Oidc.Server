// Abblix OIDC Client Library
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

using Abblix.Oidc.Client.Features.SessionManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Serves this application's session-watching frame
/// (OpenID Connect Session Management 1.0 section 3.1).
/// </summary>
/// <remarks>
/// The page is served from this application's own origin, which is what makes the arrangement work at all:
/// the frame it embeds belongs to the provider, and the two talk across origins by postMessage while each
/// stays in its own. A page served from anywhere else would be a third party to both.
/// The page that hosts this frame has one duty of its own, and nothing here can discharge it: it must
/// process messages only from this origin. Section 6 puts the mirror duty on each side of the pair, and the
/// outer page is the side outside this library.
/// </remarks>
public static class SessionCheckEndpoint
{
    /// <summary>
    /// Renders the frame for the given login state.
    /// </summary>
    /// <param name="request">The request for the frame.</param>
    /// <param name="sessionState">
    /// The login state of the current session, which the host reads from wherever it kept
    /// <see cref="CompletedSignIn.SessionState"/>.
    /// </param>
    /// <param name="cancellationToken">Cancels the metadata read.</param>
    /// <returns>
    /// The frame, or 204 when there is nothing to watch - no login state, or a provider that publishes no
    /// frame. A page framing this address gets an empty document rather than an error, because the absence
    /// of session management is not a failure of the page that asked for it.
    /// </returns>
    public static async Task<IResult> HandleAsync(
        HttpRequest request, string? sessionState, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(sessionState))
            return NothingToWatch(request);

        var services = request.HttpContext.RequestServices;

        var check = await services.GetRequiredService<IOidcClient>()
            .CreateSessionCheckAsync(sessionState, cancellationToken);

        if (check is null)
            return NothingToWatch(request);

        var frame = services.GetRequiredService<ISessionCheckFrameBuilder>()
            .Build(check, SelfOrigin(request));

        var response = request.HttpContext.Response;
        response.Headers.ContentSecurityPolicy = frame.ContentSecurityPolicy;

        // The document carries the login state of one session, so it belongs to that session and no other.
        response.Headers.CacheControl = CacheControlHeaderValue.NoStoreString;

        // The page frames a provider it names itself. Being framed in turn by anything other than this
        // application is not part of the arrangement, and the policy above says as much for a browser that
        // reads it - this says it to one that does not.
        response.Headers.XFrameOptions = "SAMEORIGIN";

        return Results.Content(frame.Html, "text/html; charset=utf-8");
    }

    private static IResult NothingToWatch(HttpRequest request)
    {
        request.HttpContext.Response.Headers.CacheControl = CacheControlHeaderValue.NoStoreString;
        return Results.NoContent();
    }

    /// <summary>
    /// The origin this application is being reached at.
    /// </summary>
    /// <remarks>
    /// Taken from the request rather than configured, so an application reachable at more than one address
    /// addresses its verdict to the one the browser actually used. A host behind a reverse proxy needs
    /// forwarded headers configured for this to be the outside address, which is the same requirement its
    /// redirect addresses already carry.
    /// </remarks>
    private static Uri SelfOrigin(HttpRequest request)
        => new($"{request.Scheme}://{request.Host}");
}
