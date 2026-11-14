// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Successful token endpoint response per RFC 6749 section 5.1, optionally extended with the OIDC Core 1.0
/// section 3.1.3.3 <c>id_token</c>.
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

	/// <summary>
	/// The RFC 9396 <c>authorization_details</c> assigned to the access token as the raw
	/// <see cref="JsonArray"/>, surfaced byte-exact in the JSON token response per RFC 9396 section 7
	/// (MUST). <c>null</c> when no RAR was used.
	/// </summary>
	public JsonArray? AuthorizationDetails { get; init; }
}
