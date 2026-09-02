// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
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
/// <param name="subjectTypeConverter">Seals a session's subject the way the requesting client sees it,
/// so the end user who authenticated can be compared against the one the request named.</param>
/// <param name="notificationService">Service for sending ping notifications.</param>
/// <param name="statusNotifier">Wakes a client waiting on a long poll. A ping client polls the token
/// endpoint the same way a poll client does, and the long-poll gate does not read the delivery mode - so
/// one that polls before its notification arrives waits, and is woken from here.</param>
public partial class PingModeCompletionHandler(
    ILogger<PingModeCompletionHandler> logger,
    IBackChannelRequestStorage storage,
    ISubjectTypeConverter subjectTypeConverter,
    INotificationDeliveryService notificationService,
    IBackChannelLongPollingService? statusNotifier = null)
    : AuthenticationCompletionHandler(logger, storage, subjectTypeConverter, statusNotifier)
{
    private readonly ILogger<AuthenticationCompletionHandler> _logger = logger;

    /// <summary>
    /// Handles ping mode delivery by storing the authenticated request and sending a notification to the client.
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

        await StoreAsync(authenticationRequestId, request, expiresIn);

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
