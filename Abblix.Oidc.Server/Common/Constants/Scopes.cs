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
