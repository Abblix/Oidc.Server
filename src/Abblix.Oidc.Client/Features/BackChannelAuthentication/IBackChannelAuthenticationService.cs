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

using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client.Features.BackChannelAuthentication;

/// <summary>
/// Asks a provider to authenticate a person on a device this client cannot see, per CIBA.
/// </summary>
/// <remarks>
/// The point of the flow is that the client and the person are in different places: a shop terminal asks,
/// the person approves on their own phone, and nothing passes through a browser here.
/// </remarks>
public interface IBackChannelAuthenticationService
{
    /// <summary>
    /// Opens the request and returns what identifies it afterwards.
    /// </summary>
    /// <param name="request">Who to ask about, and what for.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="ArgumentException">
    /// The request names no person, or names them more than one way: CIBA section 7.1 says "it is REQUIRED
    /// that the Client provides one (and only one) of the hints". Or its scopes omit <c>openid</c>, which the
    /// same section requires of every CIBA request.
    /// </exception>
    /// <exception cref="BackChannelAuthenticationException">
    /// The provider refused, could not be reached, or publishes no backchannel authentication endpoint.
    /// </exception>
    Task<BackChannelAuthenticationResponse> RequestAsync(
        BackChannelAuthenticationRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Polls the token endpoint until the person has answered, refused, or the request has expired.
    /// </summary>
    /// <param name="authentication">What <see cref="RequestAsync"/> returned.</param>
    /// <param name="cancellationToken">Stops the polling.</param>
    /// <returns>The tokens, once the person has approved.</returns>
    /// <exception cref="TokenRequestException">
    /// The request ended without tokens: the person refused it, it expired, or the provider raised an error
    /// that CIBA section 11 does not have a client poll through.
    /// </exception>
    Task<TokenResponse> WaitForTokensAsync(
        BackChannelAuthenticationResponse authentication, CancellationToken cancellationToken = default);
}
