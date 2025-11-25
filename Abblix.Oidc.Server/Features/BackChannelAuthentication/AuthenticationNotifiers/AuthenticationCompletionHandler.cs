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
/// Abstract base class for CIBA authentication completion handlers.
/// Provides common functionality for validation, status management, and delivery orchestration.
/// Derived classes implement specific token delivery modes (poll, ping, push) per CIBA specification.
/// </summary>
/// <param name="logger">Logger for tracking completion events and errors.</param>
/// <param name="storage">Storage for persisting authentication request state.</param>
public abstract class AuthenticationCompletionHandler(
    ILogger<AuthenticationCompletionHandler> logger,
    IBackChannelRequestStorage storage)
{
    /// <summary>
    /// Completes the authentication process by marking the request as authenticated and delegating
    /// to the mode-specific delivery implementation.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <param name="request">The authentication request to mark as authenticated.</param>
    /// <param name="clientInfo">Client information including delivery mode configuration.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid.</param>
    /// <returns>A task representing the asynchronous authentication completion operation.</returns>
    /// <remarks>
    /// This method:
    /// <list type="number">
    ///   <item>Sets the request status to Authenticated</item>
    ///   <item>Delegates to HandleDeliveryAsync for mode-specific token delivery (poll/ping/push)</item>
    /// </list>
    /// Called by AuthenticationCompletionRouter after determining the appropriate delivery mode handler.
    /// </remarks>
    public async Task CompleteAuthenticationAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        ClientInfo clientInfo,
        TimeSpan expiresIn)
    {
        // Update status to Authenticated before handling delivery
        request.Status = BackChannelAuthenticationStatus.Authenticated;

        await HandleDeliveryAsync(authenticationRequestId, request, clientInfo, expiresIn);
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
    protected async Task DenyRequestAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn)
    {
        request.Status = BackChannelAuthenticationStatus.Denied;
        await storage.UpdateAsync(authenticationRequestId, request, expiresIn);
    }
}
