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

namespace Abblix.Oidc.Server.Features.UserAuthentication;

/// <summary>
/// Manages user authentication, providing mechanisms to sign in, sign out, and maintain user sessions.
/// This interface plays a pivotal role in the security and session management of an application, ensuring that users are
/// authenticated and their sessions are managed securely across different contexts and client applications.
/// </summary>
public interface IAuthenticationService
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

	/// <summary>
	/// Updates or refreshes the authentication session for a specific client, typically used to extend session validity or update session details.
	/// This method supports scenarios where long-lived sessions are needed or session information needs to be refreshed due to changes in user state.
	/// </summary>
	/// <param name="authSession">The updated authentication session information.</param>
	/// <param name="clientId">The identifier of the client application for which the session is being updated.</param>
	/// <returns>A task representing the asynchronous operation to update the authentication session.</returns>
	Task UpdateAsync(AuthSession authSession, string clientId);
}
