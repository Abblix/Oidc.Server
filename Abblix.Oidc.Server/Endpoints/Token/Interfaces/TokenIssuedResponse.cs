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

using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Endpoints.Token.Interfaces;

/// <summary>
/// Represents a successful response from the token endpoint, containing the issued access token and related information.
/// </summary>
/// <param name="AccessToken">The access token issued by the authorization server.</param>
/// <param name="TokenType">The type of the token issued.</param>
/// <param name="ExpiresIn">The lifetime in seconds of the access token.</param>
/// <param name="IssuedTokenType">The URI identifying the type of the issued token.</param>
public record TokenIssuedResponse(EncodedJsonWebToken AccessToken, string TokenType, TimeSpan ExpiresIn, Uri IssuedTokenType)
	: TokenResponse
{
	/// <summary>
	/// The optional refresh token that can be used to obtain new access tokens.
	/// </summary>
	public EncodedJsonWebToken? RefreshToken { get; set; }

	/// <summary>
	/// An ID token that provides identity information about the user.
	/// </summary>
	public EncodedJsonWebToken? IdToken { get; set; }
}
