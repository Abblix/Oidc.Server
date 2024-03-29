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

using System.Text.Json.Serialization;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents the response from an OAuth 2.0 or OpenID Connect token endpoint,
/// containing details such as access token, token type, and expiration.
/// </summary>
public record TokenResponse
{
	private static class Parameters
	{
		public const string AccessToken = "access_token";
		public const string TokenType = "token_type";
		public const string IssuedTokenType = "issued_token_type";
		public const string ExpiresIn = "expires_in";
		public const string RefreshToken = "refresh_token";
		public const string IdToken = "id_token";
	}

	/// <summary>
	/// The access token issued by the authorization server. This token is used to access protected resources.
	/// </summary>
	[JsonPropertyName(Parameters.AccessToken)]
	[JsonPropertyOrder(1)]
	public string AccessToken { get; init; } = default!;

    /// <summary>
	/// The type of the issued token, typically an absolute URI identifying the token type.
	/// </summary>
	[JsonPropertyName(Parameters.IssuedTokenType)]
	[JsonPropertyOrder(2)]
	public Uri IssuedTokenType { get; set; } = default!;

	/// <summary>
	/// The type of token that is issued, usually 'Bearer'.
	/// </summary>
	[JsonPropertyName(Parameters.TokenType)]
	[JsonPropertyOrder(3)]
	public string TokenType { get; init; } = default!;

	/// <summary>
	/// The lifetime in seconds of the access token. After this duration, the token will expire and cease to be valid.
	/// </summary>
	[JsonPropertyName(Parameters.ExpiresIn)]
	[JsonPropertyOrder(4)]
	[JsonConverter(typeof(TimeSpanSecondsConverter))]
	public TimeSpan ExpiresIn { get; init; }

	/// <summary>
	/// The refresh token, which can be used to obtain new access tokens using the same authorization grant.
	/// </summary>
	[JsonPropertyName(Parameters.RefreshToken)]
	[JsonPropertyOrder(5)]
	public string? RefreshToken { get; init; }

	/// <summary>
	/// The ID token, which is a JSON Web Token (JWT) that contains the user's identity information. Present in OpenID Connect flows.
	/// </summary>
	[JsonPropertyName(Parameters.IdToken)]
	[JsonPropertyOrder(6)]
	public string? IdToken { get; init; }
}
