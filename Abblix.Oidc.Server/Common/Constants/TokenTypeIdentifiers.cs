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
/// Represents token type identifiers for various token types as specified in RFC 8693.
/// </summary>
/// <remarks>
/// See https://datatracker.ietf.org/doc/html/rfc8693#TokenTypeIdentifiers for details.
/// </remarks>
public static class TokenTypeIdentifiers
{
	/// <summary>
	/// Indicates that the token is an OAuth 2.0 access token issued by the given authorization server.
	/// </summary>
	public static Uri AccessToken = new("urn:ietf:params:oauth:token-type:access_token");

	/// <summary>
	/// Indicates that the token is an OAuth 2.0 refresh token issued by the given authorization server.
	/// </summary>
	public static Uri RefreshToken = new("urn:ietf:params:oauth:token-type:refresh_token");

	/// <summary>
	/// Indicates that the token is an ID Token as defined in Section 2 of https://openid.net/specs/openid-connect-core-1_0.html.
	/// </summary>
	public static Uri IdToken = new("urn:ietf:params:oauth:token-type:id_token");

	/// <summary>
	/// Indicates that the token is a base64url-encoded SAML 1.1 https://www.oasis-open.org/committees/download.php/3406/oasis-sstc-saml-core-1.1.pdf assertion.
	/// </summary>
	public static Uri Saml1 = new("urn:ietf:params:oauth:token-type:saml1");

	/// <summary>
	/// Indicates that the token is a base64url-encoded SAML 2.0 [http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf] assertion.
	/// </summary>
	public static Uri Saml2 = new("urn:ietf:params:oauth:token-type:saml2");
}
