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
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Helper service for updating CIBA authentication request status and sending ping notifications.
/// Use this in your IUserDeviceAuthenticationHandler implementation when user completes authentication.
/// </summary>
/// <param name="storage">Storage for authentication requests.</param>
/// <param name="notificationService">Service for sending ping notifications.</param>
/// <param name="logger">Logger for tracking notification events.</param>
public class BackChannelAuthenticationNotifier(
    IBackChannelAuthenticationStorage storage,
    IBackChannelNotificationService notificationService,
    ILogger<BackChannelAuthenticationNotifier> logger)
{
    /// <summary>
    /// Updates authentication request status to Authenticated and sends ping notification if configured.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id to update.</param>
    /// <param name="request">The updated authentication request with Authenticated status.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    public async Task NotifyAuthenticationCompleteAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        // Update storage with authenticated status
        await storage.UpdateAsync(authenticationRequestId, request, expiresIn);

        // Send ping notification if notification endpoint and token are configured
        if (request.ClientNotificationEndpoint != null &&
            request.ClientNotificationToken != null)
        {
            logger.LogInformation(
                "Sending ping notification for auth_req_id: {AuthReqId}",
                authenticationRequestId);

            await notificationService.NotifyAsync(
                request.ClientNotificationEndpoint,
                request.ClientNotificationToken,
                authenticationRequestId);
        }
        else
        {
            logger.LogDebug(
                "Poll mode - no notification sent for auth_req_id: {AuthReqId}",
                authenticationRequestId);
        }
    }
}
