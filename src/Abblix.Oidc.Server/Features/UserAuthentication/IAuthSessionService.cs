// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// Manages user authentication, providing mechanisms to sign in, sign out, and maintain user sessions.
/// This interface plays a pivotal role in the security and session management of an application, ensuring that users are
/// authenticated and their sessions are managed securely across different contexts and client applications.
/// </summary>
public interface IAuthSessionService
{
	/// <summary>
	/// Retrieves currently active authentication sessions for the user.
	/// This method is typically used to display all sessions that a user has, allowing them to manage their sessions.
	/// </summary>
	/// <returns>An asynchronous stream of <see cref="AuthSession"/> instances, each representing an active user session.</returns>
	IAsyncEnumerable<AuthSession> GetAvailableAuthSessions();

	/// <summary>
	/// Authenticates the current user based on the session context, verifying their identity and session validity.
	/// This method is crucial for ensuring that requests are made by an authenticated user and for retrieving the user's session information.
	/// </summary>
	/// <returns>
	/// A task that resolves to an <see cref="AuthSession"/> representing the authenticated user's session, or null if no valid session exists.
	/// </returns>
	Task<AuthSession?> AuthenticateAsync();

	/// <summary>
	/// Initiates a new user session based on provided user claims, effectively signing in the user.
	/// This method is essential for establishing new user sessions following successful authentication.
	/// </summary>
	/// <remarks>
	/// The implementation decides whether the sign-in ends a session the user agent already holds, and reports each
	/// one it ended. Through the service the library registers, those sessions then end as a logout ends one: their
	/// tokens are revoked when <see cref="Common.Configuration.OidcOptions.RevokeSessionTokensOnLogout"/> asks for it,
	/// and their clients receive back-channel logout notifications. Front-channel notifications are not sent, because
	/// a sign-in has no logout page to render them on.
	/// </remarks>
	/// <param name="authSession">Detailed information about the authentication session to be established.</param>
	/// <returns>The session written and the sessions the sign-in ended.</returns>
	Task<AuthSessionSignInResult> SignInAsync(AuthSession authSession);

	/// <summary>
	/// Terminates the current user session, effectively signing out the user.
	/// This method is crucial for maintaining the security of the application by ensuring that user sessions can be properly closed.
	/// </summary>
	/// <returns>A task that signifies the completion of the user sign-out process.</returns>
	Task SignOutAsync();
}
