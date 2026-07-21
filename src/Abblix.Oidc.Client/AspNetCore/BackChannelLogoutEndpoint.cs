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

using Abblix.Oidc.Client.Features.BackChannelLogout;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// The endpoint a provider posts a Logout Token to (OpenID Connect Back-Channel Logout 1.0 section 2.5).
/// </summary>
/// <remarks>
/// A request here is server-to-server, unauthenticated, and carries no session of its own: the provider is
/// not a browser and brings no cookie. Whoever can reach the address can call it, so the Logout Token is the
/// only thing that says the call is genuine, and nothing happens until it has been validated.
/// </remarks>
public static class BackChannelLogoutEndpoint
{
    /// <summary>
    /// The form parameter carrying the token, as section 2.5 names it.
    /// </summary>
    public const string LogoutTokenParameter = "logout_token";

    /// <summary>
    /// Reads the Logout Token from the request, validates it, and hands the result to
    /// <paramref name="onLogout"/> to act on.
    /// </summary>
    /// <param name="request">The request the provider posted.</param>
    /// <param name="onLogout">
    /// Ends the sessions the notification names. Section 2.7 leaves this to the RP - only the host knows
    /// where its sessions are kept - and the answer this endpoint returns reports whether it succeeded.
    /// </param>
    /// <param name="cancellationToken">Cancels the validation and the host's own work.</param>
    /// <returns>
    /// The response section 2.8 prescribes: 200 when the logout succeeded, 400 when it did not.
    /// </returns>
    /// <remarks>
    /// The failure answer is deliberately the same whatever went wrong. A provider retries or gives up on
    /// the strength of the status code, and section 2.8 offers nothing finer; saying which step failed would
    /// only tell an unauthenticated caller which of its guesses came closest.
    /// </remarks>
    public static async Task<IResult> HandleAsync(
        HttpRequest request,
        Func<LogoutNotification, CancellationToken, Task> onLogout,
        CancellationToken cancellationToken = default)
    {
        if (!HttpMethods.IsPost(request.Method) || !request.HasFormContentType)
            return Refused(request);

        var form = await request.ReadFormAsync(cancellationToken);

        if (form[LogoutTokenParameter] is not [{ } logoutToken] || string.IsNullOrEmpty(logoutToken))
            return Refused(request);

        var validator = request.HttpContext.RequestServices.GetRequiredService<ILogoutTokenValidator>();

        LogoutNotification notification;
        try
        {
            notification = await validator.ValidateAsync(logoutToken, cancellationToken);
        }
        catch (LogoutTokenValidationException)
        {
            // Section 2.6: "If any of the validation steps fails, reject the Logout Token and return an HTTP
            // 400 Bad Request error."
            return Refused(request);
        }

        await onLogout(notification, cancellationToken);

        // Section 2.8: "If the logout succeeded, the RP MUST respond with HTTP 200 OK."
        NoStore(request);
        return Results.Ok();
    }

    private static IResult Refused(HttpRequest request)
    {
        NoStore(request);
        return Results.BadRequest();
    }

    /// <summary>
    /// Section 2.8: "The RP's response SHOULD include the Cache-Control HTTP response header field with a
    /// no-store value, keeping the response from being cached to prevent cached responses from interfering
    /// with future logout requests."
    /// </summary>
    /// <remarks>
    /// Set on the failure answer as well as the success one. A cached 400 would keep answering for a token
    /// that was only invalid the first time, which is exactly the interference the header is there to
    /// prevent.
    /// </remarks>
    private static void NoStore(HttpRequest request)
        => request.HttpContext.Response.Headers.CacheControl = CacheControlHeaderValue.NoStoreString;
}
