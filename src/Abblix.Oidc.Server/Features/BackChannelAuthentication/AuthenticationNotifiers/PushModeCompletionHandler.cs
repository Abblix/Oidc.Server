// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Handles CIBA push mode token delivery where tokens are sent directly to the client's notification endpoint
/// immediately upon authentication completion.
/// In push mode the request is taken from storage, then tokens are generated and delivered via HTTP POST; a
/// request that ends without tokens is answered with the error payload of CIBA Core 1.0 section 12.
/// </summary>
/// <param name="logger">Logger for tracking notification events.</param>
/// <param name="storage">Storage for authentication requests.</param>
/// <param name="subjectTypeConverter">Seals a session's subject the way the requesting client sees it,
/// so the end user who authenticated can be compared against the one the request named.</param>
/// <param name="notificationService">Service for delivering tokens to client endpoint.</param>
/// <param name="tokenRequestProcessor">Processor for generating tokens.</param>
/// <param name="authorizationDetailsPolicy">The per-type validators, asked before delivery whether
/// the grant the host completed with is still one the deployment will issue.</param>
public partial class PushModeCompletionHandler(
    ILogger<PushModeCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    ISubjectTypeConverter subjectTypeConverter,
    INotificationDeliveryService notificationService,
    ITokenRequestProcessor tokenRequestProcessor,
    IAuthorizationDetailsPolicy authorizationDetailsPolicy)
    : AuthenticationCompletionHandler(logger, storage, subjectTypeConverter)
{
    private readonly ILogger<AuthenticationCompletionHandler> _logger = logger;

    private static readonly OidcError RefusedGrant =
        new(ErrorCodes.AccessDenied, "The grant carries authorization_details that were refused");

    private static readonly OidcError TokensNotIssued =
        new(ErrorCodes.TransactionFailed, "Tokens could not be issued for the authenticated request");

    /// <summary>
    /// Takes the request and sends the client the error, because a push client never polls.
    /// </summary>
    /// <remarks>
    /// A denied request this client cannot read is an orphan sitting in storage until it expires. CIBA Core
    /// 1.0 section 12 has the outcome travel to a push client through its notification endpoint, as an error
    /// payload - sent only by whoever took the request, the same claim delivery makes before it mints, so a
    /// refusal and a delivery racing each other answer the client once between them.
    /// </remarks>
    /// <param name="authenticationRequestId">The request refused.</param>
    /// <param name="request">The request, carrying where and with which token the client is notified.</param>
    /// <param name="refusal">The error sent.</param>
    /// <param name="expiresIn">Unused: nothing is left behind to expire.</param>
    protected override async Task RefuseAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        OidcError refusal,
        TimeSpan expiresIn)
    {
        if (await TakeRequestAsync(authenticationRequestId) is not null)
            await SendErrorAsync(authenticationRequestId, request, refusal);
    }

    /// <summary>
    /// Handles push mode token delivery: takes the request, then mints the tokens and posts them to the client.
    /// </summary>
    /// <remarks>
    /// The request is TAKEN before anything is minted, and the take is the claim. It is the one operation on
    /// the store that decides between two callers, so of a completion and an end user's refusal arriving
    /// together - or two completions - exactly one proceeds and the client is answered once: with tokens, or
    /// with an error, never both. Whoever finds the request already gone stops without a word.
    /// <para>
    /// Nothing is left behind on any path. A second completion finds no record and is refused the way every
    /// answer to a missing request is; a delivery that fails drops the tokens just minted, and the recovery is
    /// to ask the end user again.
    /// </para>
    /// </remarks>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information for token generation.</param>
    /// <param name="expiresIn">Unused: push leaves no record behind.</param>
    protected override async Task HandleDeliveryAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn)
    {
        if (!ValidateNotificationConfiguration(
            request.ClientNotificationEndpoint,
            request.ClientNotificationToken,
            BackchannelTokenDeliveryModes.Push,
            clientInfo.ClientId,
            authenticationRequestId))
        {
            // Removed rather than denied: this client never polls, so a denied request it cannot read is an
            // orphan waiting out its expiry, and with nowhere to send it no error reaches the client either.
            await TakeRequestAsync(authenticationRequestId);
            return;
        }

        if (await TakeRequestAsync(authenticationRequestId) is null)
            return;

        // The per-type validators, asked HERE because this is where a push grant is spent. Poll and ping
        // reach the same question at the token endpoint when their client redeems; a push client never
        // goes there, so without this the content of an entry whose type was requested - a raised amount,
        // a widened set of accounts - is never judged for push at all, while the identical client in
        // another mode is refused.
        //
        // The refusal's own error code and words are not what the client is sent: CIBA Core 1.0 section 12
        // allows a push error payload only access_denied, expired_token and transaction_failed, and the
        // validator's reason is written for whoever fixes the host, so it goes to the log.
        //
        // No cancellation token, because nothing on the path from the router down carries one.
        if (await authorizationDetailsPolicy.RefuseAsync(
                request.AuthorizedGrant, clientInfo, CancellationToken.None) is { } refusal)
        {
            LogGrantedAuthorizationDetailsRefused(
                authenticationRequestId, clientInfo.ClientId, refusal.Reason);

            await SendErrorAsync(authenticationRequestId, request, RefusedGrant);
            return;
        }

        LogGeneratingTokens(authenticationRequestId);

        var tokenRequest = new TokenRequest
        {
            GrantType = GrantTypes.Ciba,
            AuthenticationRequestId = authenticationRequestId,
        };

        // Says out loud that this is a push delivery, and hands over the identifier in the same breath.
        // It is what turns on the two bindings CIBA Core 1.0 Section 10.3.1 requires here and nowhere
        // else. Stated rather than left to be derived downstream, for the reasons PushDeliveryBindings
        // sets out.
        var validTokenRequest = new ValidTokenRequest(
            tokenRequest,
            request.AuthorizedGrant,
            clientInfo,
            [],
            [],
            PushDeliveryOf: authenticationRequestId);

        var tokenResult = await tokenRequestProcessor.ProcessAsync(validTokenRequest);

        await tokenResult.MatchAsync<object?>(
            async tokens =>
            {
                var payload = new BackChannelPushNotificationRequest
                {
                    AuthenticationRequestId = authenticationRequestId,
                    AccessToken = tokens.AccessToken.EncodedJwt,
                    TokenType = tokens.TokenType,
                    ExpiresIn = tokens.ExpiresIn,
                    IdToken = tokens.IdToken?.EncodedJwt,
                    RefreshToken = tokens.RefreshToken?.EncodedJwt,
                };

                var delivered = await notificationService.SendAsync(
                    request.ClientNotificationEndpoint,
                    request.ClientNotificationToken,
                    payload,
                    BackchannelTokenDeliveryModes.Push);

                // The tokens of a failed delivery are dropped with this lambda and nothing retries them.
                if (delivered)
                    LogTokensDelivered(authenticationRequestId);
                else
                    LogPushDeliveryFailed(authenticationRequestId);

                return null;
            },
            async error =>
            {
                LogTokenGenerationFailed(authenticationRequestId, error.Error);
                await SendErrorAsync(authenticationRequestId, request, TokensNotIssued);
                return null;
            });
    }

    /// <summary>
    /// Sends the push error payload of CIBA Core 1.0 section 12, by a caller that has taken the request.
    /// </summary>
    /// <remarks>
    /// The only way a push client learns its request ended without tokens. Nothing is sent where the client
    /// registered nowhere to send it.
    /// </remarks>
    private async Task SendErrorAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        OidcError refusal)
    {
        if (!ValidateNotificationConfiguration(
                request.ClientNotificationEndpoint,
                request.ClientNotificationToken,
                BackchannelTokenDeliveryModes.Push,
                request.AuthorizedGrant.Context.ClientId,
                authenticationRequestId))
        {
            return;
        }

        await notificationService.SendAsync(
            request.ClientNotificationEndpoint,
            request.ClientNotificationToken,
            new BackChannelPushErrorNotificationRequest
            {
                AuthenticationRequestId = authenticationRequestId,
                Error = refusal.Error,
                ErrorDescription = refusal.ErrorDescription,
            },
            BackchannelTokenDeliveryModes.Push);
    }
}
