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

using Abblix.Utils;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;



namespace Abblix.Oidc.Server.Common.Interfaces;

/// <summary>
/// Represents an interface for authenticating user credentials.
/// </summary>
public interface IUserCredentialsAuthenticator
{
	/// <summary>
	/// Validates user credentials (username and password) and returns a grant authorization result.
	/// </summary>
	/// <param name="userName">The username provided by the user.</param>
	/// <param name="password">The password provided by the user.</param>
	/// <param name="context">The authorization context associated with the request.</param>
	/// <returns>A task that represents the asynchronous validation operation and returns the grant authorization result.</returns>
	Task<Result<AuthorizedGrant, AuthError>> ValidateAsync(string userName, string password, AuthorizationContext context);
}
