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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// This class defines JWT (JSON Web Token) types used in various contexts.
/// </summary>
public static class JwtTypes
{
	/// <summary>
	/// The "AccessToken" JWT type is used to represent access tokens, typically used for authenticating and authorizing users in APIs.
	/// </summary>
	public const string AccessToken = "at+jwt";

	/// <summary>
	/// The "LogoutToken" JWT type is used in the context of OpenID Connect for single logout functionality.
	/// </summary>
	public const string LogoutToken = "logout+jwt";

	/// <summary>
	/// The "RefreshToken" JWT type is used to represent refresh tokens, which allow obtaining new access tokens without reauthentication.
	/// </summary>
	public const string RefreshToken = "refresh+jwt";

	/// <summary>
	/// The "RegistrationAccessToken" JWT type is used in OAuth 2.0 Dynamic Client Registration for securely registering clients.
	/// </summary>
	public const string RegistrationAccessToken = "registration+jwt";
}
