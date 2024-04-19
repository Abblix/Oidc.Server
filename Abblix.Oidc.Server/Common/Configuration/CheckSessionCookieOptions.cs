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
/// Defines options for the session check cookie used in monitoring changes in session status.
/// </summary>
public record CheckSessionCookieOptions
{
	/// <summary>
	/// The name of the cookie used to monitor session status changes. The default value is "Abblix.SessionId".
	/// </summary>
	public string Name { get; init; } = "Abblix.SessionId";

	/// <summary>
	/// The domain name where the cookie is available. Specifying the domain restricts where the cookie is sent.
	/// Leaving this value null means the cookie is sent to all subdomains.
	/// </summary>
	public string? Domain { get; set; }

	/// <summary>
	/// The SameSite attribute for the cookie which asserts that a cookie must not be sent with cross-origin requests,
	/// providing some protection against cross-site request forgery attacks (CSRF).
	/// The default value is "None", which permits the cookie to be sent with cross-site requests.
	/// Valid options are "None", "Lax", and "Strict".
	/// </summary>
	public string SameSite { get; set; } = "None";
}
