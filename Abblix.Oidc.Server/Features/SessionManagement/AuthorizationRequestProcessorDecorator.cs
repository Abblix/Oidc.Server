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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.SessionManagement;

/// <summary>
/// Enhances an existing authorization request processor with session management capabilities,
/// specifically tailored for OpenID Connect (OIDC) scenarios. This decorator introduces session
/// state handling into the authorization response, enabling clients to maintain and manage session
/// state in accordance with OpenID Connect session management specifications.
/// </summary>
/// <param name="inner">The authorization request processor to be enhanced with session management functionality.</param>
/// <param name="sessionManagementService">The session management service responsible for generating and
/// handling session state information.</param>
public class AuthorizationRequestProcessorDecorator(
    IAuthorizationRequestProcessor inner,
    ISessionManagementService sessionManagementService): IAuthorizationRequestProcessor
{

    /// <summary>
    /// Asynchronously processes an authorization request by delegating to the encapsulated authorization request processor,
    /// and then enriches the authorization response with session state information when session management is enabled and applicable.
    /// </summary>
    /// <param name="request">The authorization request to be processed, expected to be a valid and authenticated request.</param>
    /// <returns>
    /// A task that returns an <see cref="AuthorizationResponse"/>
    /// that may include session state information to be used by the client for session management purposes.
    /// </returns>
    /// <remarks>
    /// This method ensures that responses to OpenID Connect authorization requests include session state information as by
    /// the OpenID Connect session management specification. This allows clients to implement mechanisms for detecting session changes
    /// and managing user sessions effectively.
    /// </remarks>
    public async Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request)
    {
        var response = await inner.ProcessAsync(request);

        // Append session state to the response if session management is enabled and the request qualifies
        if (sessionManagementService.Enabled &&
            response is SuccessfullyAuthenticated success && success.SessionId.HasValue() &&
            request.Model.Scope.HasFlag(Scopes.OpenId))
        {
            success.SessionState = sessionManagementService.GetSessionState(request.Model, success.SessionId);
        }

        return response;
    }
}
