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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Flags to represent various OIDC endpoints.
/// </summary>
[Flags]
public enum OidcEndpoints
{
	/// <summary>
	/// All OIDC endpoints available.
	/// </summary>
	All = Configuration | Keys | Authorize | Token | UserInfo | CheckSession | EndSession | Revocation | Register |
	      PushedAuthorizationRequest,

	/// <summary>
	/// Provides OpenID Connect configuration details. Typically used during client setup.
	/// </summary>
	Configuration = 1 << 0,

	/// <summary>
	/// Provides public keys for token validation. Essential for token validation.
	/// </summary>
	Keys = 1 << 1,

	/// <summary>
	/// Used to initiate the authorization process. The starting point for user authentication.
	/// </summary>
	Authorize = 1 << 2,

	/// <summary>
	/// Used to exchange authorization codes for tokens. Part of the authentication flow.
	/// </summary>
	Token = 1 << 3,

	/// <summary>
	/// Retrieves user information after authentication. Often used to fetch user details.
	/// </summary>
	UserInfo = 1 << 4,

	/// <summary>
	/// Used for session monitoring in single sign-on scenarios. Helps track user sessions.
	/// </summary>
	CheckSession = 1 << 5,

	/// <summary>
	/// Used to end the user's session. Enables logging out the user.
	/// </summary>
	EndSession = 1 << 6,

	/// <summary>
	/// Used to revoke tokens, enhancing security by invalidating tokens.
	/// </summary>
	Revocation = 1 << 7,

	/// <summary>
	/// Used to introspect tokens.
	/// </summary>
	Introspection = 1 << 7,

	/// <summary>
	/// Used to dynamically register clients. Allows clients to register with the OIDC provider.
	/// </summary>
	Register = 1 << 8,

	PushedAuthorizationRequest = 1 << 9,
}
