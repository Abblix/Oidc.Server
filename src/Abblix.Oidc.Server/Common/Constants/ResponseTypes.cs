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
/// Represents common response types used in OAuth 2.0 and OpenID Connect flows.
/// </summary>
/// <remarks>Reference: https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html</remarks>
public static class ResponseTypes
{
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

	/// <summary>
	/// Represents the "none" response type (OAuth 2.0 Multiple Response Type Encoding Practices §4).
	/// The authorization request runs to completion but the response returns no authorization code and
	/// no tokens - only <c>state</c> and, when advertised, <c>iss</c> (RFC 9207). It authorizes a grant
	/// without returning credentials to the client at that time. This value MUST NOT be combined with
	/// any other response type.
	/// </summary>
	public const string None = "none";
}
