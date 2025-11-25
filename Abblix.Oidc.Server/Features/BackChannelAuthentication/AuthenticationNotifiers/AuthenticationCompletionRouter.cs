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

using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Routes CIBA authentication completion to the appropriate mode-specific handler
/// (PollModeCompletionHandler, PingModeCompletionHandler, or PushModeCompletionHandler) based on the client's configured
/// backchannel_token_delivery_mode.
/// </summary>
/// <param name="logger">Logger for tracking completion events.</param>
/// <param name="clientInfoProvider">Provider for retrieving client information.</param>
/// <param name="serviceProvider">Service provider for resolving mode-specific handlers using keyed services.</param>
public class AuthenticationCompletionRouter(
    ILogger<AuthenticationCompletionRouter> logger,
    IClientInfoProvider clientInfoProvider,
    IServiceProvider serviceProvider) : IAuthenticationCompletionHandler
{
    /// <summary>
    /// Completes the authentication process and handles token delivery based on the
    /// client's configured delivery mode. Automatically selects the appropriate handler implementation.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id to complete.</param>
    /// <param name="request">The authentication request to mark as completed.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    public async Task CompleteAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        var clientId = request.AuthorizedGrant.Context.ClientId;
        var clientInfo = await clientInfoProvider.TryFindClientAsync(clientId);

        if (clientInfo == null)
        {
            logger.LogError(
                "Client not found for auth_req_id: {AuthReqId}, ClientId: {ClientId}",
                authenticationRequestId,
                clientId);
            return;
        }

        var deliveryMode = clientInfo.BackChannelTokenDeliveryMode.NotNull(nameof(clientInfo.BackChannelTokenDeliveryMode));
        var handler = serviceProvider.GetRequiredKeyedService<AuthenticationCompletionHandler>(deliveryMode);
        await handler.CompleteAuthenticationAsync(authenticationRequestId, request, clientInfo, expiresIn);
    }
}
