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


namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Talks to the OpenID Provider's token endpoint.
/// </summary>
public interface ITokenRequestService
{
    /// <summary>
    /// Exchanges an authorization code for tokens.
    /// </summary>
    /// <param name="code">The code the provider returned to the callback.</param>
    /// <param name="codeVerifier">The secret half of the PKCE pair kept from the request.</param>
    /// <param name="redirectUri">
    /// The redirect address of the original request, which the provider compares against what it recorded.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="TokenRequestException">The provider refused, or could not be reached.</exception>
    Task<TokenResponse> ExchangeCodeAsync(
        string code, string codeVerifier, string redirectUri, CancellationToken cancellationToken = default);

    /// <summary>
    /// Trades a refresh token for a fresh set of tokens.
    /// </summary>
    /// <param name="refreshToken">The refresh token held for the session.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="TokenRequestException">
    /// The provider refused, or could not be reached. A refusal carrying
    /// <see cref="TokenErrorCodes.InvalidGrant"/> means this token has been rotated away.
    /// </exception>
    Task<TokenResponse> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asks for an access token on this client's own behalf, with no user involved (RFC 6749 section 4.4).
    /// </summary>
    /// <param name="scopes">
    /// What the token is being asked for. Optional per RFC 6749 section 4.4.2: pass none and the provider
    /// decides what the client's own credentials are worth.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// The provider's answer. It carries no ID Token, because there is no user to make claims about, and
    /// section 4.4.3 says a refresh token SHOULD NOT be included either - the client re-authenticates
    /// instead, which costs it nothing since its credentials are what the grant is made of.
    /// </returns>
    /// <exception cref="TokenRequestException">The provider refused, or could not be reached.</exception>
    /// <remarks>
    /// The scopes are per call rather than taken from the login configuration: a client asking for a token
    /// to call one API is not asking for what its users' sessions ask for, and the two lists have no reason
    /// to coincide.
    /// </remarks>
    Task<TokenResponse> RequestClientCredentialsAsync(
        IReadOnlyCollection<string>? scopes = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Presents one token and asks for another in its place (RFC 8693).
    /// </summary>
    /// <param name="exchange">What the exchange asks for.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// The provider's answer. What was issued is named by <see cref="TokenResponse.IssuedTokenType"/>, and
    /// it need not be what was asked for: RFC 8693 section 2.2.1 carries the issued token in
    /// <c>access_token</c> whatever its kind, with <c>token_type</c> reading <c>N_A</c> when the kind is not
    /// one that gets presented to a resource.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// An actor token was given without saying what kind it is, or the other way round. RFC 8693 section 2.1
    /// requires the type alongside the token and forbids it otherwise, so the request is refused here rather
    /// than after a round trip.
    /// </exception>
    /// <exception cref="TokenRequestException">The provider refused, or could not be reached.</exception>
    Task<TokenResponse> ExchangeTokenAsync(
        TokenExchangeParameters exchange, CancellationToken cancellationToken = default);

    /// <summary>
    /// Redeems the code a device was given, once its user has authorized it elsewhere (RFC 8628 section 3.4).
    /// </summary>
    /// <param name="deviceCode">The code from the device authorization response.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="TokenRequestException">
    /// The provider refused, or could not be reached. One call is one attempt, and most of its refusals are
    /// not final: <see cref="TokenErrorCodes.AuthorizationPending"/> and
    /// <see cref="TokenErrorCodes.SlowDown"/> both mean "ask again later". Polling in accordance with them is
    /// what <c>IDeviceAuthorizationService</c> does, and a caller driving this method itself owes the same
    /// rules.
    /// </exception>
    Task<TokenResponse> RedeemDeviceCodeAsync(
        string deviceCode, CancellationToken cancellationToken = default);
}
