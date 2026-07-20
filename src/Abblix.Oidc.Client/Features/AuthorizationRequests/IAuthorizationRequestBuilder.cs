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

namespace Abblix.Oidc.Client.Features.AuthorizationRequests;

/// <summary>
/// Builds the request that sends a user to the OpenID Provider to sign in.
/// </summary>
public interface IAuthorizationRequestBuilder
{
    /// <summary>
    /// Builds the address to send the user to, and puts aside everything needed to judge their return.
    /// </summary>
    /// <param name="returnUri">
    /// Where the user was heading before sign-in was required, relative to this application.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="AuthorizationRequestException">
    /// The provider offers nowhere to send the user, or <paramref name="returnUri"/> is not relative.
    /// </exception>
    /// <remarks>
    /// The return address must be relative, and an absolute one is refused rather than trusted. In
    /// practice this value arrives from the request that triggered the login, which makes it
    /// user-agent-supplied, and a client that redirects to whatever it is handed is an open redirector
    /// (RFC 6749 section 10.15, RFC 9700 section 4.11). A same-origin absolute address would be
    /// harmless, but nothing in this package knows the application's origin to compare against, so
    /// "relative" is the strongest rule that can be enforced here rather than merely recommended.
    /// Do not confuse it with <see cref="AuthorizationRequestOptions.RedirectUri"/>, which is resolved
    /// by the provider rather than the application and must therefore be absolute.
    /// </remarks>
    Task<AuthorizationRequest> CreateAsync(Uri returnUri, CancellationToken cancellationToken = default);
}
