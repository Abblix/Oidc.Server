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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the authorization process for backchannel authentication requests under the Client-Initiated Backchannel
/// Authentication (CIBA) grant type.
/// This handler validates the token request based on the backchannel authentication flow, ensuring
/// that the client is authorized and that the user has been authenticated before tokens are issued.
/// Supports both short-polling (immediate response) and long-polling (holds connection until auth completes).
/// </summary>
/// <param name="storage">Service for storing and retrieving backchannel authentication requests.</param>
/// <param name="parameterValidator">The service to validate request parameters.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
/// <param name="options">Configuration options for backchannel authentication including long-polling settings.</param>
/// <param name="serviceProvider">Service provider for resolving mode-specific grant processors.</param>
/// <param name="statusNotifier">Notifier for long-polling status changes (null if long-polling disabled).</param>
/// <param name="httpContextAccessor">Accessor for HTTP context to retrieve cancellation token.</param>
public class BackChannelAuthenticationGrantHandler(
    IBackChannelRequestStorage storage,
    IParameterValidator parameterValidator,
    TimeProvider timeProvider,
    IOptions<OidcOptions> options,
    IServiceProvider serviceProvider,
    IBackChannelLongPollingService? statusNotifier = null,
    IHttpContextAccessor? httpContextAccessor = null) : IAuthorizationGrantHandler
{
    /// <summary>
    /// Specifies the grant types supported by this handler, specifically the "CIBA" (Client-Initiated Backchannel
    /// Authentication) grant type.
    /// This property ensures that the handler is only invoked for the specific grant type it supports.
    /// </summary>
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.Ciba; }
    }

    /// <summary>
    /// Processes the authorization request by verifying the authentication request ID and checking the status of the
    /// associated backchannel authentication request. Supports both short-polling (immediate response) and optional
    /// long-polling (holds connection until authentication completes or timeout).
    /// </summary>
    /// <remarks>
    /// <para><strong>Behavior by Authentication Status:</strong></para>
    /// <list type="bullet">
    ///   <item><term>Authenticated:</term> Returns authorized grant and removes from storage (poll mode only)</item>
    ///   <item><term>Pending (short-polling):</term> Immediately returns authorization_pending error</item>
    ///   <item><term>Pending (long-polling):</term> Waits for status change notification up to configured timeout,
    ///   then re-checks storage to return grant or appropriate error</item>
    ///   <item><term>Denied:</term> Returns access_denied error</item>
    ///   <item><term>Expired/Not Found:</term> Returns expired_token error</item>
    ///   <item><term>Rate Limited:</term> Returns slow_down error if polled before NextPollAt</item>
    /// </list>
    /// <para>
    /// Long-polling reduces latency (0-1s vs 0-5s) and server load (1-4 req/min vs 12 req/min) by holding the
    /// connection open until authentication completes instead of requiring repeated polling.
    /// </para>
    /// </remarks>
    /// <param name="request">The token request containing the authentication request ID and other parameters.</param>
    /// <param name="clientInfo">Information about the client making the request, used to validate client identity
    /// and determine token delivery mode (poll/ping/push).</param>
    /// <returns>
    /// Either an authorized grant if authentication succeeded, or an error indicating why the request failed
    /// (authorization_pending, access_denied, expired_token, slow_down, or invalid_grant).
    /// </returns>
    public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        // Check if the request contains a valid authentication request ID
        parameterValidator.Required(request.AuthenticationRequestId, nameof(request.AuthenticationRequestId));

        // Try to retrieve the corresponding backchannel authentication request from storage
        var authenticationRequest = await storage.TryGetAsync(request.AuthenticationRequestId);

        // Resolve mode-specific grant processor using keyed service
        // Delivery mode is validated at backchannel authentication request time by ClientValidator
        var processor = serviceProvider.GetRequiredKeyedService<IBackChannelGrantProcessor>(
            clientInfo.BackChannelTokenDeliveryMode.NotNull(nameof(clientInfo.BackChannelTokenDeliveryMode)));

        // Validate that the client is allowed to access the token endpoint for this mode
        var accessError = processor.ValidateTokenEndpointAccess();
        if (accessError != null)
        {
            return accessError;
        }

        // Determine the outcome of the authorization based on the state of the backchannel authentication request
        return authenticationRequest switch
        {
            // If the request is not found or has expired, return an error indicating token expiration
            null => new OidcError(ErrorCodes.ExpiredToken, "The authentication request has expired"),

            // If the client making the request is not the same as the one that initiated the authentication
            // This validation MUST occur before any status-specific processing for security
            { AuthorizedGrant.Context.ClientId: var clientId } when clientId != clientInfo.ClientId
                => new OidcError(ErrorCodes.InvalidGrant, "The authentication request was issued to another client"),

            // If the user has been authenticated, process mode-specific token retrieval
            { Status: BackChannelAuthenticationStatus.Authenticated }
                => await processor.ProcessAuthenticatedRequestAsync(request.AuthenticationRequestId, authenticationRequest),

            // If the request is still pending and not yet time to poll again
            { Status: BackChannelAuthenticationStatus.Pending, NextPollAt: { } nextPollAt }
                when timeProvider.GetUtcNow() < nextPollAt
                => new OidcError(ErrorCodes.SlowDown, "The authorization request is still pending as the user hasn't been authenticated"),

            // If the user has not yet been authenticated and the request is still pending,
            // either wait for status change (long-polling) or return immediately (short-polling)
            { Status: BackChannelAuthenticationStatus.Pending } pendingRequest
                => await HandlePendingRequestAsync(request.AuthenticationRequestId, pendingRequest, clientInfo),

            // If the user denied the authentication request, return an error indicating access is denied
            { Status: BackChannelAuthenticationStatus.Denied }
                => new OidcError(ErrorCodes.AccessDenied, "The authorization request is denied by the user."),

            _ => throw new InvalidOperationException(
                $"The authentication request status is unexpected: {authenticationRequest.Status}.")
        };
    }

    /// <summary>
    /// Handles pending authentication requests with optional long-polling support.
    /// Updates NextPollAt to enforce rate limiting on subsequent polls, then attempts long-polling if enabled,
    /// otherwise returns authorization_pending immediately.
    /// </summary>
    /// <remarks>
    /// Note: There is a benign race condition between TryGetAsync (line 106) and UpdateAsync where concurrent
    /// poll requests could overwrite each other's NextPollAt updates. This is acceptable because:
    /// 1. The rate limiting check (line 136) happens BEFORE this method is called
    /// 2. Any concurrent update will set NextPollAt to approximately the same time (now + interval)
    /// 3. The worst case is slightly inconsistent polling intervals, not security vulnerability
    /// 4. Proper fix would require compare-and-swap or optimistic locking at storage layer
    /// </remarks>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="authenticationRequest">The pending authentication request to update.</param>
    /// <param name="clientInfo">Client information for determining token delivery mode.</param>
    /// <returns>Either an authorized grant if authentication completed during long-polling, or authorization_pending error.</returns>
    private async Task<Result<AuthorizedGrant, OidcError>> HandlePendingRequestAsync(
        string authenticationRequestId,
        Features.BackChannelAuthentication.BackChannelAuthenticationRequest authenticationRequest,
        ClientInfo clientInfo)
    {
        // Calculate remaining time before expiration
        var expiresIn = authenticationRequest.ExpiresAt - timeProvider.GetUtcNow();
        if (expiresIn <= TimeSpan.Zero)
        {
            // Request has expired, remove it
            await storage.TryRemoveAsync(authenticationRequestId);
            return new OidcError(ErrorCodes.ExpiredToken, "The authentication request has expired");
        }

        // Update NextPollAt to enforce rate limiting for the next poll
        // This prevents clients from spamming polls after the initial interval expires
        var pollingInterval = options.Value.BackChannelAuthentication.PollingInterval;
        authenticationRequest.NextPollAt = timeProvider.GetUtcNow() + pollingInterval;

        // Update the request in storage with new NextPollAt
        // Note: This update is not atomic with the read above, see method remarks
        await storage.UpdateAsync(authenticationRequestId, authenticationRequest, expiresIn);

        if (options.Value.BackChannelAuthentication.UseLongPolling && statusNotifier != null)
        {
            var result = await TryLongPollingAsync(authenticationRequestId, clientInfo);
            if (result != null)
            {
                return result;
            }
        }

        return new OidcError(
            ErrorCodes.AuthorizationPending,
            "The authorization request is still pending. " +
            "The polling interval must be increased by at least 5 seconds for all subsequent requests.");
    }

    /// <summary>
    /// Attempts long-polling for status change notification.
    /// </summary>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="clientInfo">Client information for determining token delivery mode.</param>
    /// <returns>
    /// The result of processing the updated request if status changed, or null if timeout occurred.
    /// Null indicates the caller should return authorization_pending error.
    /// </returns>
    private async Task<Result<AuthorizedGrant, OidcError>?> TryLongPollingAsync(
        string authenticationRequestId,
        ClientInfo clientInfo)
    {
        var statusChanged = await statusNotifier!.WaitForStatusChangeAsync(
            authenticationRequestId,
            options.Value.BackChannelAuthentication.LongPollingTimeout,
            httpContextAccessor?.HttpContext?.RequestAborted ?? CancellationToken.None);

        if (!statusChanged)
        {
            return null;
        }

        var updatedRequest = await storage.TryGetAsync(authenticationRequestId);
        return await ProcessUpdatedRequest(updatedRequest, authenticationRequestId, clientInfo);
    }

    /// <summary>
    /// Processes the updated authentication request after status change notification.
    /// Handles Authenticated, Denied, and Expired states appropriately.
    /// </summary>
    /// <param name="updatedRequest">The updated authentication request from storage, or null if expired.</param>
    /// <param name="authenticationRequestId">The authentication request identifier.</param>
    /// <param name="clientInfo">Client information for determining token delivery mode.</param>
    /// <returns>Either an authorized grant, access denied error, expired token error, or authorization_pending.</returns>
    private async Task<Result<AuthorizedGrant, OidcError>> ProcessUpdatedRequest(
        Features.BackChannelAuthentication.BackChannelAuthenticationRequest? updatedRequest,
        string authenticationRequestId,
        ClientInfo clientInfo)
    {
        // Validate client ownership before processing (security critical)
        if (updatedRequest?.AuthorizedGrant.Context.ClientId != clientInfo.ClientId)
        {
            return new OidcError(ErrorCodes.InvalidGrant, "The authentication request was issued to another client");
        }

        // Resolve mode-specific grant processor
        var grantProcessor = serviceProvider.GetRequiredKeyedService<IBackChannelGrantProcessor>(
            clientInfo.BackChannelTokenDeliveryMode);

        switch (updatedRequest)
        {
            case { Status: BackChannelAuthenticationStatus.Authenticated }:
                return await grantProcessor.ProcessAuthenticatedRequestAsync(
                    authenticationRequestId,
                    updatedRequest);

            case { Status: BackChannelAuthenticationStatus.Denied }:
                return new OidcError(
                    ErrorCodes.AccessDenied,
                    "The authorization request is denied by the user.");

            case null:
                return new OidcError(
                    ErrorCodes.ExpiredToken,
                    "The authentication request has expired");

            default:
                return new OidcError(
                    ErrorCodes.AuthorizationPending,
                    "The authorization request is still pending. " +
                    "The polling interval must be increased by at least 5 seconds for all subsequent requests.");
        }
    }
}
