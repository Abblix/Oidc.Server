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

using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;


namespace Abblix.Oidc.Server.Endpoints.CheckSession;

/// <summary>
/// Processes check session requests in accordance with OpenID Connect Session Management.
/// This class interacts with a session management service to determine the current authentication status
/// of an end-user with the OpenID Provider. It's an integral part of maintaining session integrity and security,
/// allowing the application to respond to changes in the user's authentication status in a timely and efficient manner.
/// </summary>
internal class CheckSessionHandler : ICheckSessionHandler
{
	/// <summary>
	/// Initializes a new instance of the <see cref="CheckSessionHandler"/> class.
	/// Sets up the necessary session management service to handle OpenID Connect session checks.
	/// </summary>
	/// <param name="sessionManagementService">The service responsible for managing and verifying session states.</param>
	public CheckSessionHandler(ISessionManagementService sessionManagementService)
	{
		_sessionManagementService = sessionManagementService;
	}

	private readonly ISessionManagementService _sessionManagementService;

	/// <inheritdoc />
	/// <summary>
	/// Processes a check session request asynchronously, leveraging the session management service
	/// to assess the current state of the user's session. This method is key to ensuring that the
	/// application's understanding of the user's session status is accurate and up-to-date.
	/// </summary>
	/// <returns>
	/// A <see cref="Task"/> that, when completed, yields a <see cref="CheckSessionResponse"/>
	/// indicating the current state of the user's session.
	/// </returns>
	public Task<CheckSessionResponse> HandleAsync() => _sessionManagementService.GetCheckSessionResponseAsync();
}
