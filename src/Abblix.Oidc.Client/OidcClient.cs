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
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using Abblix.Oidc.Client.Features.BackChannelLogout;
using Abblix.Oidc.Client.Features.EndSession;
using Abblix.Oidc.Client.Features.IdentityTokens;
using Abblix.Oidc.Client.Features.Principal;
using Abblix.Oidc.Client.Features.Revocation;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Client.Features.UserInfo;

namespace Abblix.Oidc.Client;

/// <summary>
/// Composes the client's features into the operations a host actually performs.
/// </summary>
/// <param name="requestBuilder">Builds authorization requests.</param>
/// <param name="responseHandler">Accepts what comes back to the redirection endpoint.</param>
/// <param name="tokenRequestService">Talks to the token endpoint.</param>
/// <param name="identityTokenValidator">Validates ID Tokens against what the request asked for.</param>
/// <param name="principalFactory">Turns a validated ID Token into the signed-in user.</param>
/// <param name="userInfoService">Reads the UserInfo endpoint.</param>
/// <param name="revocationService">Revokes tokens.</param>
/// <param name="endSessionRequestBuilder">Builds logout addresses.</param>
/// <param name="logoutTokenValidator">Validates Logout Tokens the provider posts.</param>
public sealed class OidcClient(
    IAuthorizationRequestBuilder requestBuilder,
    IAuthorizationResponseHandler responseHandler,
    ITokenRequestService tokenRequestService,
    IIdentityTokenValidator identityTokenValidator,
    IClaimsPrincipalFactory principalFactory,
    IUserInfoService userInfoService,
    ITokenRevocationService revocationService,
    IEndSessionRequestBuilder endSessionRequestBuilder,
    ILogoutTokenValidator logoutTokenValidator) : IOidcClient
{
    /// <inheritdoc />
    public Task<AuthorizationRequest> CreateAuthorizationRequestAsync(
        Uri returnUri, CancellationToken cancellationToken = default)
        => requestBuilder.CreateAsync(returnUri, cancellationToken);

    /// <inheritdoc />
    public async Task<CompletedSignIn> HandleCallbackAsync(
        IReadOnlyDictionary<string, IReadOnlyList<string>> parameters,
        CancellationToken cancellationToken = default)
    {
        // Everything that decides whether this response may be acted on at all: it matches a login this
        // client started, it came from the provider that login was started with, and any ID Token it carried
        // through the browser is valid. Nothing below runs otherwise.
        var response = await responseHandler.HandleAsync(parameters, cancellationToken);

        return response.Code is { } code
            ? await CompleteWithCodeAsync(response, code, cancellationToken)
            : CompleteWithFrontChannelTokens(response);
    }

    /// <inheritdoc />
    public Task<TokenResponse> RefreshAsync(
        string refreshToken, CancellationToken cancellationToken = default)
        => tokenRequestService.RefreshAsync(refreshToken, cancellationToken);

    /// <inheritdoc />
    public Task RevokeAsync(
        string token, string? tokenTypeHint = null, CancellationToken cancellationToken = default)
        => revocationService.RevokeAsync(token, tokenTypeHint, cancellationToken);

    /// <inheritdoc />
    public Task<JsonObject> GetUserInfoAsync(
        string accessToken, string expectedSubject, CancellationToken cancellationToken = default)
        => userInfoService.GetAsync(accessToken, expectedSubject, cancellationToken);

    /// <inheritdoc />
    public Task<Uri> CreateEndSessionRequestAsync(
        string identityToken,
        string? state = null,
        string? logoutHint = null,
        CancellationToken cancellationToken = default)
        => endSessionRequestBuilder.CreateAsync(identityToken, state, logoutHint, cancellationToken);

    /// <inheritdoc />
    public Task<LogoutNotification> ValidateBackChannelLogoutAsync(
        string logoutToken, CancellationToken cancellationToken = default)
        => logoutTokenValidator.ValidateAsync(logoutToken, cancellationToken);

    /// <summary>
    /// Redeems the code and validates the ID Token the token endpoint returns.
    /// </summary>
    private async Task<CompletedSignIn> CompleteWithCodeAsync(
        AuthorizationResult response, string code, CancellationToken cancellationToken)
    {
        var context = response.Context;

        var tokens = await tokenRequestService.ExchangeCodeAsync(
            code, context.CodeVerifier, context.RedirectUri, cancellationToken);

        if (tokens.IdToken is not { } encodedIdentityToken)
        {
            throw new TokenRequestException(
                "The token endpoint returned no ID Token, so there is no authenticated user to sign in. A "
                + "provider answers a request carrying the openid scope with one.");
        }

        var identityToken = await identityTokenValidator.ValidateAsync(
            encodedIdentityToken,
            new IdentityTokenValidationContext
            {
                // OIDC Core 1.0 section 3.1.3.7 step 11: "If a nonce value was sent in the Authentication
                // Request, a nonce Claim MUST be present and its value checked to verify that it is the same
                // value as the one that was sent."
                Nonce = context.Nonce,

                // Checked only where the token carries the matching hash, which for a token-endpoint ID
                // Token it usually does not. Passed anyway so that a provider which does include one is held
                // to it rather than trusted for the courtesy.
                AccessToken = tokens.AccessToken,
                AuthorizationCode = code,
            },
            cancellationToken);

        RequireSameSubject(response.IdToken, identityToken);

        return new CompletedSignIn(
            principalFactory.Create(identityToken),
            identityToken,
            encodedIdentityToken,
            tokens.AccessToken,
            tokens.RefreshToken,

            // The token endpoint states the lifetime in seconds (RFC 6749 section 5.1); the authorization
            // endpoint's answer was already turned into a span while the response was parsed, so both
            // arrive here in the same shape.
            tokens.ExpiresIn is { } seconds ? TimeSpan.FromSeconds(seconds) : null,
            context.ReturnUri);
    }

    /// <summary>
    /// Signs in from what the authorization endpoint itself returned, for the flows that issue tokens there.
    /// </summary>
    /// <remarks>
    /// The ID Token was already validated while handling the response, where the nonce and the hashes that
    /// bind it to this request were still checkable.
    /// </remarks>
    private CompletedSignIn CompleteWithFrontChannelTokens(AuthorizationResult response)
    {
        if (response.IdToken is not { } identityToken)
        {
            throw new AuthorizationResponseException(
                "The response carried neither an authorization code nor an ID Token, so there is no "
                + "authenticated user to sign in.");
        }

        return new CompletedSignIn(
            principalFactory.Create(identityToken),
            identityToken,
            EncodedIdentityToken(response),
            response.AccessToken,

            // A refresh token never travels through the browser: RFC 9700 section 2.2.2 confines it to the
            // token endpoint, and this flow does not visit it.
            RefreshToken: null,
            response.ExpiresIn,
            response.Context.ReturnUri);
    }

    /// <summary>
    /// Refuses a hybrid login whose two ID Tokens describe different users.
    /// </summary>
    /// <remarks>
    /// Our own check, not a clause quoted from the specification. In the hybrid flow one ID Token comes back
    /// through the browser and another from the token endpoint, and each is valid on its own terms - same
    /// issuer, same audience, same nonce. If they name different subjects, one of them is not about the user
    /// this login authenticated, and building a principal would mean picking one and hoping. There is no
    /// legitimate way for a provider to answer one request with two ID Tokens about two people, so the
    /// disagreement itself is the reason to stop.
    /// </remarks>
    private static void RequireSameSubject(JsonWebToken? frontChannelToken, JsonWebToken identityToken)
    {
        if (frontChannelToken is null)
            return;

        if (!string.Equals(
                frontChannelToken.Payload.Subject, identityToken.Payload.Subject, StringComparison.Ordinal))
        {
            throw new IdentityTokenValidationException(
                "The ID Token from the token endpoint describes a different subject than the one that "
                + "arrived through the browser, so this login identifies no one user.");
        }
    }

    /// <summary>
    /// The ID Token exactly as it arrived, which logging out needs.
    /// </summary>
    private static string EncodedIdentityToken(AuthorizationResult response)
        => response.EncodedIdToken
           ?? throw new AuthorizationResponseException(
               "The response carried a validated ID Token but not the text it arrived as.");
}
