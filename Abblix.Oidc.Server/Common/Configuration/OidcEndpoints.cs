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
