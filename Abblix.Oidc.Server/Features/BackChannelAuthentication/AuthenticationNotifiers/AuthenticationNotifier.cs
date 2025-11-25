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

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

/// <summary>
/// Abstract base class for CIBA authentication completion notification handlers.
/// Provides common functionality for client lookup, validation, and status notification.
/// Derived classes implement specific token delivery modes (poll, ping, push).
/// </summary>
/// <param name="logger">Logger for tracking notification events.</param>
/// <param name="storage">Storage for authentication requests.</param>
/// <param name="clientInfoProvider">Provider for retrieving client information.</param>
/// <param name="statusNotifier">Notifier for long-polling status changes (null if long-polling disabled).</param>
public abstract class AuthenticationNotifier(
    ILogger<AuthenticationNotifier> logger,
    IBackChannelRequestStorage storage,
    IClientInfoProvider clientInfoProvider,
    IBackChannelLongPollingService? statusNotifier): IAuthenticationNotifier
{
    /// <summary>
    /// Updates authentication request status to Authenticated and handles token delivery based on the delivery mode.
    /// Also notifies waiting long-polling requests to wake up and retrieve tokens.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id to update.</param>
    /// <param name="request">The authentication request to mark as authenticated.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    public async Task NotifyAsync(
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

        // Update status to Authenticated before handling delivery
        request.Status = BackChannelAuthenticationStatus.Authenticated;

        await HandleDeliveryAsync(authenticationRequestId, request, clientInfo, expiresIn);

        if (statusNotifier != null)
        {
            await statusNotifier.NotifyStatusChangeAsync(
                authenticationRequestId,
                request.Status);
        }
    }

    /// <summary>
    /// Handles the token delivery according to the specific delivery mode (poll, ping, or push).
    /// Derived classes implement the specific delivery logic for their mode.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authenticated request containing the authorized grant.</param>
    /// <param name="clientInfo">Client information including delivery mode configuration.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid.</param>
    protected abstract Task HandleDeliveryAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn);

    /// <summary>
    /// Validates that the required notification endpoint and bearer token are configured.
    /// Both are mandatory for ping and push modes per CIBA specification.
    /// </summary>
    /// <param name="endpoint">The client notification endpoint.</param>
    /// <param name="token">The client notification token.</param>
    /// <param name="deliveryMode">Name of the mode for logging (e.g., "Push mode", "Ping mode").</param>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <returns>True if both endpoint and token are present; otherwise, false.</returns>
    protected bool ValidateNotificationConfiguration(
        [NotNullWhen(true)] Uri? endpoint,
        [NotNullWhen(true)] string? token,
        string deliveryMode,
        string clientId,
        string authenticationRequestId)
    {
        var hasToken = token != null;
        if (hasToken && endpoint != null)
            return true;

        logger.LogError(
            "{ModeName} client missing notification endpoint or token. " +
            "ClientId: {ClientId}, auth_req_id: {AuthReqId}, " +
            "Endpoint: {Endpoint}, Token: {HasToken}",
            deliveryMode,
            clientId,
            authenticationRequestId,
            endpoint?.ToString() ?? "null",
            hasToken);

        return false;
    }

    /// <summary>
    /// Marks the authentication request as denied and persists the status to storage.
    /// This is used when configuration errors or token generation failures prevent successful authentication.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="request">The authentication request to mark as denied.</param>
    /// <param name="expiresIn">How long the denied status remains in storage for client polling.</param>
    protected async Task SetRequestAsDeniedAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        request.Status = BackChannelAuthenticationStatus.Denied;
        await storage.UpdateAsync(authenticationRequestId, request, expiresIn);
    }
}
