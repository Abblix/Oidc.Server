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
/// Represents common response modes used in OAuth 2.0 and OpenID Connect flows.
/// </summary>
public static class ResponseModes
{
	/// <summary>
	/// Represents the "form_post" response mode, where the response parameters are encoded as HTML form values and
	/// sent as a POST request to the redirect URI.
	/// </summary>
	public const string FormPost = "form_post";

	/// <summary>
	/// Represents the "query" response mode, where the response parameters are appended as query parameters to the
	/// redirect URI.
	/// </summary>
	public const string Query = "query";

	/// <summary>
	/// Represents the "fragment" response mode, where the response parameters are appended as URL fragments to the
	/// redirect URI.
	/// </summary>
	public const string Fragment = "fragment";
}
