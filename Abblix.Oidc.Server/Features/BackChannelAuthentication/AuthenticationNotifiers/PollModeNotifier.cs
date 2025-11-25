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
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Handles CIBA poll mode token delivery where the client periodically polls the token endpoint to retrieve tokens.
/// In poll mode, the authenticated request is stored and remains available until the client retrieves it or it expires.
/// </summary>
/// <param name="logger">Logger for tracking notification events.</param>
/// <param name="storage">Storage for authentication requests.</param>
/// <param name="clientInfoProvider">Provider for retrieving client information.</param>
/// <param name="statusNotifier">Notifier for long-polling status changes (null if long-polling disabled).</param>
public class PollModeNotifier(
    ILogger<AuthenticationNotifier> logger,
    IBackChannelRequestStorage storage,
    IClientInfoProvider clientInfoProvider,
    IBackChannelLongPollingService? statusNotifier)
    : AuthenticationNotifier(logger, storage, clientInfoProvider, statusNotifier)
{
    private readonly ILogger<AuthenticationNotifier> _logger = logger;
    private readonly IBackChannelRequestStorage _storage = storage;

    /// <summary>
    /// Handles poll mode token delivery by storing the authenticated request in storage.
    /// The client will periodically poll the token endpoint to retrieve tokens.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information (not used in poll mode).</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    protected override async Task HandleDeliveryAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn)
    {
        await _storage.UpdateAsync(authenticationRequestId, request, expiresIn);
        _logger.LogDebug("Poll mode - tokens stored for auth_req_id: {AuthReqId}", authenticationRequestId);
    }
}
