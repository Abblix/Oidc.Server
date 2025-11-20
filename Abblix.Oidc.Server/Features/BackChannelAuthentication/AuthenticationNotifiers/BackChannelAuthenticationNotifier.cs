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
/// Composite notifier that automatically selects and delegates to the appropriate mode-specific notifier
/// (PollModeNotifier, PingModeNotifier, or PushModeNotifier) based on the client's configured
/// backchannel_token_delivery_mode.
/// </summary>
/// <param name="logger">Logger for tracking notification events.</param>
/// <param name="clientInfoProvider">Provider for retrieving client information.</param>
/// <param name="serviceProvider">Service provider for resolving mode-specific notifiers using keyed services.</param>
public class BackChannelAuthenticationNotifier(
    ILogger<BackChannelAuthenticationNotifier> logger,
    IClientInfoProvider clientInfoProvider,
    IServiceProvider serviceProvider) : IBackChannelAuthenticationNotifier
{
    /// <summary>
    /// Updates authentication request status to Authenticated and handles token delivery based on the
    /// client's configured delivery mode. Automatically selects the appropriate notifier implementation.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id to update.</param>
    /// <param name="request">The updated authentication request with Authenticated status.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    public async Task NotifyAuthenticationCompleteAsync(
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

        // Resolve mode-specific notifier using keyed service
        // Delivery mode is validated at backchannel authentication request time by ClientValidator
        var notifier = serviceProvider.GetRequiredKeyedService<AuthenticationNotifier>(
            clientInfo.BackChannelTokenDeliveryMode.NotNull(nameof(clientInfo.BackChannelTokenDeliveryMode)));

        await notifier.NotifyAuthenticationCompleteAsync(
            authenticationRequestId,
            request,
            expiresIn);
    }
}
