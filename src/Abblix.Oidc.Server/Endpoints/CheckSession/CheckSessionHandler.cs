// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;


namespace Abblix.Oidc.Server.Endpoints.CheckSession;

/// <summary>
/// Processes check session requests in accordance with OpenID Connect Session Management.
/// This class interacts with a session management service to determine the current authentication status
/// of an end-user with the OpenID Provider. It's an integral part of maintaining session integrity and security,
/// allowing the application to respond to changes in the user's authentication status in a timely and efficient manner.
/// </summary>
internal class CheckSessionHandler(ISessionManagementService sessionManagementService) : ICheckSessionHandler
{
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
	public Task<CheckSessionResponse> HandleAsync() => sessionManagementService.GetCheckSessionResponseAsync();
}
