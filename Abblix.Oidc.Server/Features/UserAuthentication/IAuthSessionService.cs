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
	/// <param name="authSession">Detailed information about the authentication session to be established.</param>
	/// <returns>A task that signifies the completion of the user sign-in process.</returns>
	Task SignInAsync(AuthSession authSession);

	/// <summary>
	/// Terminates the current user session, effectively signing out the user.
	/// This method is crucial for maintaining the security of the application by ensuring that user sessions can be properly closed.
	/// </summary>
	/// <returns>A task that signifies the completion of the user sign-out process.</returns>
	Task SignOutAsync();
}
