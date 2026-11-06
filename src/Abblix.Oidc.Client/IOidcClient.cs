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

using System.Text.Json.Nodes;
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.Revocation;
using Abblix.Oidc.Client.Features.SessionManagement;
using Abblix.Oidc.Client.Features.Tokens;

namespace Abblix.Oidc.Client;

/// <summary>
/// The whole client behind one contract: start a login, finish it, and everything that follows.
/// </summary>
/// <remarks>
/// The individual services stay public and usable on their own; this adds the compositions that would
/// otherwise be written by every host, and written differently each time. Finishing a login is the one that
/// matters: handling the callback, redeeming the code, validating the ID Token against what the request
/// asked for and building a principal are four steps whose order is the security, and a host is not the
/// right place for them to be assembled by hand.
/// </remarks>
public interface IOidcClient
{
    /// <summary>
    /// Starts a login and returns where to send the user.
    /// </summary>
    /// <param name="returnUri">
    /// Where the user was heading, relative to this application, so the login can put them back there.
    /// </param>
    /// <param name="parameters">
    /// What this particular login asks of the provider: how recent the authentication must be, which
    /// assurance it must carry, which account to hint at, how the provider should present itself. Omitted
    /// entirely when the caller asks for nothing special.
    /// A silent request goes here too, as <see cref="Prompts.None"/> in
    /// <see cref="AuthorizationRequestParameters.Prompt"/>. This is how OpenID Connect Session Management
    /// 1.0 section 2 has a client re-check a session it was told had changed: the request goes in an
    /// invisible frame, so a login screen must not appear in it.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    Task<AuthorizationRequest> CreateAuthorizationRequestAsync(
        Uri returnUri,
        AuthorizationRequestParameters? parameters = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Finishes the login the given callback belongs to.
    /// </summary>
    /// <param name="parameters">
    /// What arrived at the redirection endpoint, as name and values. Names may repeat, which is itself
    /// something the client checks rather than something a caller should collapse first.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>The signed-in user and the tokens the login produced.</returns>
    /// <remarks>
    /// Throws rather than returning a failure, so there is no shape in which a caller holds a principal
    /// nobody validated.
    /// </remarks>
    Task<CompletedSignIn> HandleCallbackAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string>> parameters,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Trades a refresh token for a fresh set.
    /// </summary>
    Task<TokenResponse> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asks the provider to revoke a token this client holds (RFC 7009).
    /// </summary>
    /// <remarks>
    /// Returning normally means the provider answered that the token is gone, which it also answers about a
    /// token it never knew. <see cref="TokenRevocationException.TokenMayStillExist"/> distinguishes a
    /// failure that leaves the token live.
    /// </remarks>
    Task RevokeAsync(
        string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Asks the provider what it will say about the user an access token was issued for.
    /// </summary>
    /// <param name="accessToken">The access token to present.</param>
    /// <param name="expectedSubject">
    /// The subject of the ID Token this login produced. Required, because OIDC Core 1.0 section 5.3.2 makes
    /// comparing the two the client's duty.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    Task<JsonObject> GetUserInfoAsync(
        string accessToken, string expectedSubject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Builds the address that ends the user's session at the provider.
    /// </summary>
    /// <param name="identityToken">
    /// The ID Token this login produced, as it arrived, sent as <c>id_token_hint</c>.
    /// </param>
    /// <param name="state">An opaque value the provider echoes back, when the caller wants one.</param>
    /// <param name="logoutHint">A hint about which end-user is logging out, when the provider documents one.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    Task<Uri> CreateEndSessionRequestAsync(
        string identityToken,
        string? state = null,
        string? logoutHint = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gathers what a page needs in order to watch whether the end-user is still logged in at the provider.
    /// </summary>
    /// <param name="sessionState">
    /// The login state from the most recent authorization response, which
    /// <see cref="CompletedSignIn.SessionState"/> carries.
    /// </param>
    /// <param name="cancellationToken">Cancels the metadata read.</param>
    /// <returns>
    /// The values the page needs, or <c>null</c> when the provider publishes no session-management frame -
    /// which is an answer, not a failure.
    /// </returns>
    /// <remarks>
    /// The watching happens in the browser between two frames and cannot happen here; this only spells the
    /// values so they are not assembled by hand.
    /// </remarks>
    Task<SessionCheck?> CreateSessionCheckAsync(
        string sessionState, CancellationToken cancellationToken = default);
}
