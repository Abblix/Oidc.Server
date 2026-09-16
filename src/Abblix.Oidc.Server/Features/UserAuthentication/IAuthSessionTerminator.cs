// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.LogoutNotification;

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// Ends a session for the tokens issued in it and for the clients signed in to it.
/// </summary>
/// <remarks>
/// A session ends on logout and when a sign-in replaces it, and both go through here so the two cannot drift
/// apart. Removing the session from the user agent is the caller's part.
/// </remarks>
public interface IAuthSessionTerminator
{
    /// <summary>
    /// Revokes the tokens of the session when the deployment asks for it, then notifies its clients.
    /// </summary>
    /// <param name="sessionId">The session that ended.</param>
    /// <param name="subject">The end user the session belonged to.</param>
    /// <returns>
    /// The logout context the notifiers filled in, whose front-channel URIs a logout renders to the user agent.
    /// </returns>
    Task<LogoutContext> TerminateAsync(string sessionId, string subject);
}
