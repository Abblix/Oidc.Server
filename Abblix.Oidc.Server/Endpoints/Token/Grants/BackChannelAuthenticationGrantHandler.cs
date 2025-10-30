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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the authorization process for backchannel authentication requests under the Client-Initiated Backchannel
/// Authentication (CIBA) grant type.
/// This handler validates the token request based on the backchannel authentication flow, ensuring
/// that the client is authorized and that the user has been authenticated before tokens are issued.
/// </summary>
/// <param name="storage">Service for storing and retrieving backchannel authentication requests.</param>
/// <param name="parameterValidator">The service to validate request parameters.</param>
/// <param name="timeProvider">Provides access to the current time.</param>
public class BackChannelAuthenticationGrantHandler(
    IBackChannelAuthenticationStorage storage,
    IParameterValidator parameterValidator,
    TimeProvider timeProvider) : IAuthorizationGrantHandler
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
    /// associated backchannel authentication request. This method retrieves the authentication request from storage
    /// and determines if the request is authorized, still pending, denied or expired. Based on the status, it returns
    /// either a success result with the authorized grant or an error result indicating why the request can't be
    /// processed.
    /// </summary>
    /// <param name="request">The token request containing the authentication request ID and other parameters.</param>
    /// <param name="clientInfo">Information about the client making the request, used to validate client identity.
    /// </param>
    /// <returns>
    /// A <see cref="GrantAuthorizationResult"/> indicating the outcome of the authorization process.
    /// This could be a valid grant if the user has been authenticated, or an error if the request is pending, denied
    /// or invalid.
    /// </returns>
    public async Task<Result<AuthorizedGrant, AuthError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
    {
        // Check if the request contains a valid authentication request ID
        parameterValidator.Required(request.AuthenticationRequestId, nameof(request.AuthenticationRequestId));

        // Try to retrieve the corresponding backchannel authentication request from storage
        var authenticationRequest = await storage.TryGetAsync(request.AuthenticationRequestId);

        // Determine the outcome of the authorization based on the state of the backchannel authentication request
        switch (authenticationRequest)
        {
            // If the user has been authenticated, remove the request and return the authorized grant
            case { Status: BackChannelAuthenticationStatus.Authenticated, AuthorizedGrant: { } authorizedGrant }:
                await storage.RemoveAsync(request.AuthenticationRequestId);
                return authorizedGrant;

            // If the request is not found or has expired, return an error indicating token expiration
            case null:
                return new AuthError(
                    ErrorCodes.ExpiredToken,
                    "The authentication request has expired");

            // If the client making the request is not the same as the one that initiated the authentication
            case { AuthorizedGrant.Context.ClientId: var clientId } when clientId != clientInfo.ClientId:
                return new AuthError(
                    ErrorCodes.UnauthorizedClient,
                    "The authentication request was started by another client");

            // If the request is still pending and not yet time to poll again
            case { Status: BackChannelAuthenticationStatus.Pending, NextPollAt: {} nextPollAt }
                when timeProvider.GetUtcNow() < nextPollAt:

                return new AuthError(
                    ErrorCodes.SlowDown,
                    "The authorization request is still pending as the user hasn't been authenticated");

            // If the user has not yet been authenticated and the request is still pending,
            // return an error indicating that authorization is pending
            case { Status: BackChannelAuthenticationStatus.Pending }:
                return new AuthError(
                    ErrorCodes.AuthorizationPending,
                    "The authorization request is still pending. " +
                    "The polling interval must be increased by at least 5 seconds for all subsequent requests.");

            // If the user denied the authentication request, return an error indicating access is denied
            case { Status: BackChannelAuthenticationStatus.Denied }:
                return new AuthError(
                    ErrorCodes.AccessDenied,
                    "The authorization request is denied by the user.");

            // Capture any unexpected case as an exception
            default:
                throw new InvalidOperationException(
                    $"The authentication request status is unexpected: {authenticationRequest.Status}.");
        }
    }
}
