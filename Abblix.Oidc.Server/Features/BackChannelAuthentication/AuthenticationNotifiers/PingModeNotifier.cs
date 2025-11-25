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
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Handles CIBA ping mode token delivery where the client receives a notification that authentication is complete
/// and can then retrieve tokens from the token endpoint.
/// In ping mode, the authenticated request is stored and a notification is sent to the client's registered endpoint.
/// </summary>
/// <param name="logger">Logger for tracking notification events.</param>
/// <param name="storage">Storage for authentication requests.</param>
/// <param name="clientInfoProvider">Provider for retrieving client information.</param>
/// <param name="statusNotifier">Notifier for long-polling status changes (null if long-polling disabled).</param>
/// <param name="notificationService">Service for sending ping notifications.</param>
public class PingModeNotifier(
    ILogger<AuthenticationNotifier> logger,
    IBackChannelRequestStorage storage,
    IClientInfoProvider clientInfoProvider,
    IBackChannelLongPollingService? statusNotifier,
    INotificationDeliveryService notificationService)
    : AuthenticationNotifier(logger, storage, clientInfoProvider, statusNotifier)
{
    private readonly ILogger<AuthenticationNotifier> _logger = logger;
    private readonly IBackChannelRequestStorage _storage = storage;

    /// <summary>
    /// Handles ping mode token delivery by storing tokens and sending a notification to the client.
    /// The client will poll the token endpoint after receiving the notification.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information for validation.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    protected override async Task HandleDeliveryAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn)
    {
        if (!ValidateNotificationConfiguration(
            request.ClientNotificationEndpoint,
            request.ClientNotificationToken,
            BackchannelTokenDeliveryModes.Ping,
            clientInfo.ClientId,
            authenticationRequestId))
        {
            await SetRequestAsDeniedAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        await _storage.UpdateAsync(authenticationRequestId, request, expiresIn);

        _logger.LogInformation(
            "Sending ping notification for auth_req_id: {AuthReqId}",
            authenticationRequestId);

        var payload = new BackChannelPingNotificationRequest
        {
            AuthenticationRequestId = authenticationRequestId,
        };

        await notificationService.SendAsync(
            request.ClientNotificationEndpoint,
            request.ClientNotificationToken,
            payload,
            BackchannelTokenDeliveryModes.Ping);
    }
}
