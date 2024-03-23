// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
public class AuthorizationRequestProcessorDecorator: IAuthorizationRequestProcessor
{
    /// <summary>
    /// Constructs an instance of <see cref="AuthorizationRequestProcessorDecorator"/> with a specified
    /// authorization request processor and session management service.
    /// </summary>
    /// <param name="inner">The authorization request processor to be enhanced with session management functionality.</param>
    /// <param name="sessionManagementService">The session management service responsible for generating and
    /// handling session state information.</param>
    public AuthorizationRequestProcessorDecorator(
        IAuthorizationRequestProcessor inner,
        ISessionManagementService sessionManagementService)
    {
        _inner = inner;
        _sessionManagementService = sessionManagementService;
    }

    private readonly IAuthorizationRequestProcessor _inner;
    private readonly ISessionManagementService _sessionManagementService;

    /// <summary>
    /// Asynchronously processes an authorization request by delegating to the encapsulated authorization request processor,
    /// and then enriches the authorization response with session state information when session management is enabled and applicable.
    /// </summary>
    /// <param name="request">The authorization request to be processed, expected to be a valid and authenticated request.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. Upon completion, the task yields an <see cref="AuthorizationResponse"/>
    /// that may include session state information to be used by the client for session management purposes.
    /// </returns>
    /// <remarks>
    /// This method ensures that responses to OpenID Connect authorization requests include session state information as by
    /// the OpenID Connect session management specification. This allows clients to implement mechanisms for detecting session changes
    /// and managing user sessions effectively.
    /// </remarks>
    public async Task<AuthorizationResponse> ProcessAsync(ValidAuthorizationRequest request)
    {
        var response = await _inner.ProcessAsync(request);

        // Append session state to the response if session management is enabled and the request qualifies
        if (_sessionManagementService.Enabled &&
            response is SuccessfullyAuthenticated success && success.SessionId.HasValue() &&
            request.Model.Scope.HasFlag(Scopes.OpenId))
        {
            success.SessionState = _sessionManagementService.GetSessionState(request.Model, success.SessionId);
        }

        return response;
    }
}
