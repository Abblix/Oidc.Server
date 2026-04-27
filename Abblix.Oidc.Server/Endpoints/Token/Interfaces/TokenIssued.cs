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

using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Successful token endpoint response per RFC 6749 §5.1, optionally extended with the OIDC Core 1.0
/// §3.1.3.3 <c>id_token</c>.
/// </summary>
/// <param name="AccessToken">The issued access token (<c>access_token</c>).</param>
/// <param name="TokenType">The <c>token_type</c>, typically <c>Bearer</c> (RFC 6750).</param>
/// <param name="ExpiresIn">Lifetime returned as <c>expires_in</c>.</param>
/// <param name="IssuedTokenType">URI identifying the type of the issued token, used by RFC 8693 token exchange.</param>
public record TokenIssued(EncodedJsonWebToken AccessToken, string TokenType, TimeSpan ExpiresIn, Uri IssuedTokenType)
{
	/// <summary>
	/// The optional refresh token that can be used to obtain new access tokens.
	/// </summary>
	public EncodedJsonWebToken? RefreshToken { get; set; }

	/// <summary>
	/// An ID token that provides identity information about the user.
	/// </summary>
	public EncodedJsonWebToken? IdToken { get; set; }

	/// <summary>
	/// The scopes associated with the access token issued. Scopes indicate the permissions granted to the access token.
	/// </summary>
	public IEnumerable<string> Scope => AccessToken.Token.Payload.Scope;
}
