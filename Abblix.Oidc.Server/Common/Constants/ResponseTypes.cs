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
/// Represents common response types used in OAuth 2.0 and OpenID Connect flows.
/// </summary>
/// <remarks>Reference: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html</remarks>
public static class ResponseTypes
{
	/// <summary>
	/// Represents the "none" response type, indicating no specific response type is requested.
	/// This is typically used when the client does not expect a response or when only error handling is needed.
	/// </summary>
	public const string None = "none";

	/// <summary>
	/// Represents the "code" response type, indicating the authorization code response type.
	/// This is used in the Authorization Code Flow to request an authorization code for later exchange.
	/// </summary>
	public const string Code = "code";

	/// <summary>
	/// Represents the "token" response type, indicating the token response type.
	/// This is used in Implicit Flow to directly issue tokens to the client without using an authorization code.
	/// </summary>
	public const string Token = "token";

	/// <summary>
	/// Represents the "id_token" response type, indicating the ID token response type.
	/// This is used to request only an ID token in the response, typically in OpenID Connect scenarios.
	/// </summary>
	public const string IdToken = "id_token";
}
