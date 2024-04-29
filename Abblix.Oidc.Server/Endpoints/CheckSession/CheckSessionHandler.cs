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
