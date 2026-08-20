// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// Delegates to the wrapped processor and, when session management is enabled and the response is a successful
    /// OpenID Connect authentication, attaches the OIDC Session Management 1.0 <c>session_state</c> value so the
    /// client's <c>check_session_iframe</c> can detect session changes.
    /// </summary>
    /// <param name="request">The authorization request to be processed, expected to be a valid and authenticated request.</param>
    /// <returns>
    /// The inner processor's <see cref="AuthorizationResponse"/>, with <c>session_state</c> populated when applicable.
    /// </returns>
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
