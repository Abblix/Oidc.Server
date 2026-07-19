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
	public static readonly Uri AccessToken = new("urn:ietf:params:oauth:token-type:access_token");

	/// <summary>
	/// Indicates that the token is an OAuth 2.0 refresh token issued by the given authorization server.
	/// </summary>
	public static readonly Uri RefreshToken = new("urn:ietf:params:oauth:token-type:refresh_token");

	/// <summary>
	/// Indicates that the token is an ID Token as defined in Section 2 of https://openid.net/specs/openid-connect-core-1_0.html.
	/// </summary>
	public static readonly Uri IdToken = new("urn:ietf:params:oauth:token-type:id_token");

	/// <summary>
	/// Indicates that the token is a base64url-encoded SAML 1.1 https://www.oasis-open.org/committees/download.php/3406/oasis-sstc-saml-core-1.1.pdf assertion.
	/// </summary>
	public static readonly Uri Saml1 = new("urn:ietf:params:oauth:token-type:saml1");

	/// <summary>
	/// Indicates that the token is a base64url-encoded SAML 2.0 [http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf] assertion.
	/// </summary>
	public static readonly Uri Saml2 = new("urn:ietf:params:oauth:token-type:saml2");
}
