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

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Client.Features.FrontChannelLogout;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// The address a provider renders in a frame to log this client out
/// (OpenID Connect Front-Channel Logout 1.0 section 2).
/// </summary>
/// <remarks>
/// What arrives here is a browser being told to load a page. Section 2 describes the mechanism plainly - the
/// OP renders an iframe whose source is this address - and that is the whole of it: no token, no signature,
/// nothing that says the request came from the provider rather than from any page the user happened to
/// visit. Section 2 asks the RP to "clear state associated with the logged-in session, including any cookies
/// and HTML5 local storage", and that is the right size of action for a request of this kind: ending a local
/// session costs the user a sign-in, and no more.
/// The address itself carries a constraint worth registering correctly: section 2 requires that the scheme,
/// domain and port "MUST be the same as that of a registered Redirection URI value", which the provider
/// enforces at registration.
/// </remarks>
public static class FrontChannelLogoutEndpoint
{
    /// <summary>
    /// Reads the request and hands what it says to <paramref name="onLogout"/> to act on.
    /// </summary>
    /// <param name="request">The request the browser was told to load.</param>
    /// <param name="onLogout">
    /// Ends the local session. Only the host knows where its session is kept, and section 2 leaves the
    /// clearing to it.
    /// </param>
    /// <param name="cancellationToken">Cancels the read and the host's own work.</param>
    /// <returns>
    /// An empty 200 when the request was acted on, 400 when it was not one this client acts on.
    /// </returns>
    /// <remarks>
    /// The body is empty on purpose. The response is rendered inside a frame on the provider's logout page
    /// and nobody reads it; anything drawn here would be a page fragment appearing in someone else's
    /// document.
    /// </remarks>
    public static async Task<IResult> HandleAsync(
        HttpRequest request,
        Func<FrontChannelLogoutNotification, CancellationToken, Task> onLogout,
        CancellationToken cancellationToken = default)
    {
        // Section 2 shows the address rendered as an iframe source, which a browser fetches with GET.
        if (!HttpMethods.IsGet(request.Method))
            return Refused(request);

        var reader = request.HttpContext.RequestServices
            .GetRequiredService<IFrontChannelLogoutRequestReader>();

        FrontChannelLogoutNotification notification;
        try
        {
            notification = await reader.ReadAsync(ReadParameters(request), cancellationToken);
        }
        catch (FrontChannelLogoutException)
        {
            return Refused(request);
        }

        await onLogout(notification, cancellationToken);

        NoStore(request);
        return Results.NoContent();
    }

    private static IResult Refused(HttpRequest request)
    {
        NoStore(request);
        return Results.BadRequest();
    }

    /// <summary>
    /// Section 2: "The RP's response SHOULD include the Cache-Control HTTP response header field with a
    /// no-store value, keeping the response from being cached to prevent cached responses from interfering
    /// with future logout requests."
    /// </summary>
    private static void NoStore(HttpRequest request)
        => request.HttpContext.Response.Headers.CacheControl = CacheControlHeaderValue.NoStoreString;

    [SuppressMessage("SonarQube", "S1905:Redundant casts should not be used",
        Justification = "Not redundant: the cast is what makes the dictionary's value type string?, which "
            + "the declared return type asks for. Removing it produces CS8619 - a Dictionary<string, string> "
            + "where an IReadOnlyDictionary<string, string?> is expected - so the build refuses it. The rule "
            + "misses this because the analysis does not compile the project and so reads no nullable "
            + "context.")]
    private static IReadOnlyDictionary<string, string?> ReadParameters(HttpRequest request)
        => request.Query.ToDictionary(
            entry => entry.Key,

            // A parameter repeated in the query is not one of two answers to pick from. Joining the values
            // keeps the repeat visible, so it fails the issuer comparison rather than being silently
            // resolved in favour of whichever came first.
            entry => (string?)string.Join(',', entry.Value.Select(value => value ?? string.Empty)),
            StringComparer.Ordinal);
}
