// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Features.SessionManagement;

/// <summary>
/// Provides methods and properties for managing user sessions in the context of an OpenID Connect or OAuth 2.0 authorization server.
/// This interface enables the implementation of session management features, such as creating session cookies,
/// generating session state values and processing check session requests.
/// </summary>
public interface ISessionManagementService
{
    /// <summary>
    /// Gets a value indicating whether session management is enabled and available for use in the authorization server.
    /// When <c>true</c>, session management features are active and can be utilized to track and manage user sessions.
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    /// Retrieves the session cookie that is used for managing the user's session. This cookie can be used to persist session
    /// information across browser requests and to facilitate session management operations.
    /// </summary>
    /// <returns>A <see cref="Cookie"/> object configured for session management, containing details such as the cookie name,
    /// value, path, and security settings.</returns>
    Cookie GetSessionCookie();

    /// <summary>
    /// Generates a session state string that represents the current state of the user's session. This string can be used
    /// to validate the session's integrity and to detect session changes or logout events in a front-channel logout scenario.
    /// </summary>
    /// <param name="request">The authorization request context, which may contain parameters influencing the session state generation.</param>
    /// <param name="sessionId">A unique identifier for the user's session. This ID is used as part of the session state generation process.</param>
    /// <returns>A session state string that represents the hashed state of the session, including the session ID and other relevant factors.</returns>
    string GetSessionState(AuthorizationRequest request, string sessionId);

    /// <summary>
    /// Asynchronously retrieves the response for a session check operation. This method is called to process check session requests,
    /// allowing the client to query the current state of the user's session and detect any changes.
    /// </summary>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation, yielding a <see cref="CheckSessionResponse"/> object that
    /// contains the necessary information for the client to evaluate the session state.</returns>
    Task<CheckSessionResponse> GetCheckSessionResponseAsync();
}
