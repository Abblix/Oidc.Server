// Abblix OIDC Server Library
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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Handles CIBA push mode token delivery where tokens are sent directly to the client's notification endpoint
/// immediately upon authentication completion.
/// In push mode, tokens are generated, delivered via HTTP POST, and the request is removed from storage per CIBA spec 10.3.1.
/// </summary>
/// <param name="logger">Logger for tracking notification events.</param>
/// <param name="storage">Storage for authentication requests.</param>
/// <param name="notificationService">Service for delivering tokens to client endpoint.</param>
/// <param name="tokenRequestProcessor">Processor for generating tokens.</param>
public class PushModeCompletionHandler(
    ILogger<AuthenticationCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    INotificationDeliveryService notificationService,
    ITokenRequestProcessor tokenRequestProcessor)
    : AuthenticationCompletionHandler(logger, storage)
{
    private readonly ILogger<AuthenticationCompletionHandler> _logger = logger;
    private readonly IBackChannelRequestStorage _storage = storage;

    /// <summary>
    /// Handles push mode token delivery by generating tokens and delivering them directly to the client endpoint.
    /// The authentication request is removed from storage after successful delivery per CIBA spec 10.3.1.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information for token generation.</param>
    /// <param name="expiresIn">How long the request remains in storage if token generation fails.</param>
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
            await DenyRequestAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        _logger.LogInformation(
            "Generating and delivering tokens via CIBA push mode for auth_req_id: {AuthReqId}",
            authenticationRequestId);

        var tokenRequest = new TokenRequest
        {
            GrantType = GrantTypes.Ciba,
            AuthenticationRequestId = authenticationRequestId,
        };

        var validTokenRequest = new ValidTokenRequest(
            tokenRequest,
            request.AuthorizedGrant,
            clientInfo,
            [],
            []);

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

                await notificationService.SendAsync(
                    request.ClientNotificationEndpoint,
                    request.ClientNotificationToken,
                    payload,
                    BackchannelTokenDeliveryModes.Push);

                // Per CIBA spec 10.3.1, remove after push delivery (unlike poll/ping modes)
                await _storage.TryRemoveAsync(authenticationRequestId);

                _logger.LogInformation(
                    "Tokens delivered via CIBA push mode for auth_req_id: {AuthReqId}",
                    authenticationRequestId);

                return null;
            },
            async error =>
            {
                _logger.LogError(
                    "Failed to generate tokens for CIBA push mode, auth_req_id: {AuthReqId}, Error: {ErrorCode}",
                    authenticationRequestId,
                    error.Error);

                // Per CIBA spec 10.3.1, remove from storage after push attempt (success or failure)
                // Push mode clients cannot poll, so storing denied status would orphan the request
                await _storage.TryRemoveAsync(authenticationRequestId);

                return null;
            });
    }
}
