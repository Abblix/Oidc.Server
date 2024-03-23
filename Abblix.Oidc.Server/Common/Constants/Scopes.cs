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
/// Represents common OAuth 2.0 and OpenID Connect scopes.
/// </summary>
public static class Scopes
{
	/// <summary>
	/// The "openid" scope is used to indicate that the request is an OpenID Connect request,
	/// allowing the identity of the user to be included in the response.
	/// </summary>
	public const string OpenId = "openid";

	/// <summary>
	/// The "profile" scope is used to request access to the user's profile information,
	/// such as their name, picture, and other profile-related details.
	/// </summary>
	public const string Profile = "profile";

	/// <summary>
	/// The "email" scope is used to request access to the user's email address.
	/// </summary>
	public const string Email = "email";

	/// <summary>
	/// The "phone" scope is used to request access to the user's phone number.
	/// </summary>
	public const string Phone = "phone";

	/// <summary>
	/// The "offline_access" scope is used to request a refresh token that allows the client
	/// to obtain new access tokens without user interaction.
	/// </summary>
	public const string OfflineAccess = "offline_access";

	/// <summary>
	/// The "address" scope is used to request access to the user's physical address information.
	/// </summary>
	public const string Address = "address";
}
