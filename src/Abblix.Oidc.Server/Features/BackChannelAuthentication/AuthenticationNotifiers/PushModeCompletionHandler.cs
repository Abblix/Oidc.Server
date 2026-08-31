// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// In push mode, tokens are generated, delivered via HTTP POST, and the request is removed from storage -
/// except when the delivery itself fails, which is the one outcome that leaves the record behind.
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
    private readonly IBackChannelRequestStorage _storage = storage;

    /// <summary>
    /// Removes the request rather than denying it, because a push client never polls.
    /// </summary>
    /// <remarks>
    /// A denied request this client cannot read is an orphan sitting in storage until it expires, which is
    /// why the token-generation failure below removes one too. CIBA Core 1.0 Section 10.3.1 has the outcome
    /// travel to a push client through the notification endpoint, and this server does not send an error
    /// payload there - so nothing is delivered either way, and the difference is only what is left behind.
    /// </remarks>
    protected override Task RefuseAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
        => _storage.TryRemoveAsync(authenticationRequestId);

    /// <summary>
    /// Handles push mode token delivery by generating tokens and delivering them directly to the client endpoint.
    /// The status transition is persisted before the tokens are minted, and the request is removed after
    /// a delivery that succeeded. The WRITE is the protection: it leaves a record a sequential retry is
    /// refused by, on the one path where a record survives. The removal is hygiene now that the write
    /// exists - what it would otherwise leave is an Authenticated orphan that the completion handler and
    /// the token endpoint both already refuse, waiting out its expiry. The write is the same one poll and ping make, so it
    /// carries the whole record including the grant the host completed with.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information for token generation.</param>
    /// <param name="expiresIn">The lifetime applied when the status transition is persisted, which is
    /// what a record surviving a failed delivery then expires on. Push writes once and only for that,
    /// so a delivery that succeeds removes the record long before the lifetime matters.</param>
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
            // Removed rather than denied, for the reason RefuseAsync above states: this client never
            // polls, so a denied request it cannot read is an orphan waiting out its expiry.
            await RefuseAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        // The per-type validators, asked HERE because this is where a push grant is spent. Poll and ping
        // reach the same question at the token endpoint when their client redeems; a push client never
        // goes there, so without this the content of an entry whose type was requested - a raised amount,
        // a widened set of accounts - is never judged for push at all, while the identical client in
        // another mode is refused.
        //
        // Asked after the configuration check rather than before it, so a client that cannot be delivered
        // to does not spend a validator's round trip, and so the log names the fault an operator has to
        // fix first. Both outcomes remove the request either way.
        //
        // The refusal's own error code is discarded, unlike at the token endpoint: nothing carries an
        // error to a push client. CIBA Core 1.0 Section 10.3.1 has the outcome travel through the
        // notification endpoint, and this server sends no error payload there.
        //
        // No cancellation token, because nothing on the path from the router down carries one.
        if (await authorizationDetailsPolicy.RefuseAsync(
                request.AuthorizedGrant, clientInfo, CancellationToken.None) is { } refusal)
        {
            LogGrantedAuthorizationDetailsRefused(
                authenticationRequestId, clientInfo.ClientId, refusal.Reason);

            await RefuseAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        // Persisted BEFORE minting, and this is the only write push makes. The property the order buys
        // is that no token set can exist over a record still reading Pending, and writing first makes it
        // hold whatever runs afterwards. Any placement after the mint leaves a window instead: a fault, a
        // crash or a cancellation between minting and the write leaves a full token set alive over a
        // record the base handler would still complete - the hole this closes, reopened narrower.
        //
        // Not "otherwise it would never happen on the failure path". A write inside the delivery-failed
        // branch runs on that path perfectly well and the failing-delivery row stays green; it is the
        // span before it that stops being covered.
        //
        // The whole record, the same way poll and ping write theirs: the storage serializes the object it
        // is handed, so the grant the host completed with goes down with the status. What stops a second
        // completion is not anything the record omits - it is the base handler reading this status back
        // and refusing everything that is not Pending. A record that carried the status alone would be
        // just as unusable and harder to explain.
        //
        // On the delivery path this write is undone moments later by the removal below. That is a wasted
        // round trip on the successful case in exchange for the guarantee on the failing one, which is
        // the case that mints tokens nobody asked for.
        await _storage.UpdateAsync(authenticationRequestId, request, expiresIn);

        LogGeneratingTokens(authenticationRequestId);

        var tokenRequest = new TokenRequest
        {
            GrantType = GrantTypes.Ciba,
            AuthenticationRequestId = authenticationRequestId,
        };

        // Says out loud that this is a push delivery, because nothing downstream can tell: poll and ping
        // reach the token endpoint with the same grant type and the same identifier. It is what turns on
        // the two bindings CIBA Core 1.0 Section 10.3.1 requires here and nowhere else.
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

                if (delivered)
                {
                    // Removed here and not in poll or ping mode, because only this client is finished
                    // with the request: it has the tokens and will never come to the token endpoint.
                    // CIBA Core 1.0 does not require this - section 10.3.1 says nothing about what the OP
                    // keeps - so it is a choice, made because the alternative is an orphan.
                    await _storage.TryRemoveAsync(authenticationRequestId);
                    LogTokensDelivered(authenticationRequestId);
                }
                else
                {
                    // Delivery failed, and the tokens just minted are dropped with this lambda - nothing
                    // retries them.
                    //
                    // What survives in storage reads Authenticated, written above before anything was
                    // minted, and carries the grant the end user actually approved along with the
                    // session naming them. Before that write it was the PRE-completion record - Pending,
                    // carrying what the client asked for - and it had everything CompleteAsync needed
                    // except any sign it had been used, which is what made handing it back an over-grant
                    // rather than a retry.
                    //
                    // The status is what closes that: the base handler reads it from storage and
                    // completes only a Pending request.
                    //
                    // It is kept rather than removed so a host can see the request existed, and it expires
                    // on its own. The correct recovery is to ask the end user again, which is what the
                    // refusal now makes the only one available.
                    LogPushDeliveryFailed(authenticationRequestId);
                }

                return null;
            },
            async error =>
            {
                LogTokenGenerationFailed(authenticationRequestId, error.Error);

                // No tokens were minted, so there is nothing a second attempt could deliver and nothing
                // for a host to complete again. Removed rather than marked denied, because a push client
                // never polls and would never read the mark. Not a requirement of CIBA Core 1.0.
                await _storage.TryRemoveAsync(authenticationRequestId);

                return null;
            });
    }
}
