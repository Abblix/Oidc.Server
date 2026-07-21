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

using Abblix.Oidc.Client.Features.Authorization.Requests;
using Microsoft.AspNetCore.Http;

namespace Abblix.Oidc.Client.AspNetCore;

/// <summary>
/// Starts a login from an ASP.NET Core endpoint: builds the authorization request and redirects the
/// browser to the provider.
/// </summary>
public static class AuthorizationRequestBuilderExtensions
{
    /// <summary>
    /// Builds the authorization request for <paramref name="returnUri"/> and returns the redirect that
    /// sends the browser to the provider to sign in.
    /// </summary>
    /// <param name="builder">The builder that produces the request and puts its context aside.</param>
    /// <param name="returnUri">Where to send the user once the login finishes, relative to this application.</param>
    /// <param name="cancellationToken">Cancels the metadata read the build needs.</param>
    /// <returns>A 302 redirect to the provider's authorization endpoint.</returns>
    /// <remarks>
    /// The order matters and is the builder's to guarantee: it stores the login's context before this
    /// returns, and for a cookie- or cache-backed store that store writes its cookie onto the current
    /// response. The redirect this produces is written onto the same response, so the <c>Set-Cookie</c>
    /// and the <c>Location</c> leave together - the browser is bound to the login in the very response
    /// that sends it away. A redirect issued before the context was stored would let the callback arrive
    /// for a login that does not exist yet.
    /// </remarks>
    public static async Task<IResult> ChallengeAsync(
        this IAuthorizationRequestBuilder builder,
        Uri returnUri,
        CancellationToken cancellationToken = default)
    {
        var request = await builder.CreateAsync(returnUri, silent: false, cancellationToken);

        return Results.Redirect(request.RequestUri.ToString());
    }

    /// <summary>
    /// The same, taking the return address as a string. It must be relative, which the builder enforces.
    /// </summary>
    /// <param name="builder">The builder that produces the request and puts its context aside.</param>
    /// <param name="returnUri">A relative return address, such as the path the user was heading to.</param>
    /// <param name="cancellationToken">Cancels the metadata read the build needs.</param>
    /// <returns>A 302 redirect to the provider's authorization endpoint.</returns>
    public static Task<IResult> ChallengeAsync(
        this IAuthorizationRequestBuilder builder,
        string returnUri,
        CancellationToken cancellationToken = default)
    {
        return builder.ChallengeAsync(new Uri(returnUri, UriKind.Relative), cancellationToken);
    }
}
