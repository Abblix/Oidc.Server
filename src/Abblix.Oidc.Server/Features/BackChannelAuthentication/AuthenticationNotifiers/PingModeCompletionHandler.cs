// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// <param name="notificationService">Service for sending ping notifications.</param>
public partial class PingModeCompletionHandler(
    ILogger<PingModeCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    INotificationDeliveryService notificationService)
    : AuthenticationCompletionHandler(logger, storage)
{
    private readonly ILogger<AuthenticationCompletionHandler> _logger = logger;
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
            await DenyRequestAsync(authenticationRequestId, request, expiresIn);
            return;
        }

        await _storage.UpdateAsync(authenticationRequestId, request, expiresIn);

        LogSendingPingNotification(authenticationRequestId);

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
