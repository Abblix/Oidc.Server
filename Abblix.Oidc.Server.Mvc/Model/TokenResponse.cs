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
		public const string Scope = "scope";
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
	public Uri? IssuedTokenType { get; set; }

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
	/// The scope of the access token as granted by the resource owner. If omitted, the authorization server SHOULD
	/// return the same scope as requested or the full scope granted when different from the requested scope.
	/// </summary>
	[JsonPropertyName(Parameters.Scope)]
	[JsonPropertyOrder(6)]
	[JsonConverter(typeof(SpaceSeparatedValuesConverter))]
	public string[]? Scope { get; init; }

	/// <summary>
	/// The ID token, which is a JSON Web Token (JWT) that contains the user's identity information. Present in OpenID Connect flows.
	/// </summary>
	[JsonPropertyName(Parameters.IdToken)]
	[JsonPropertyOrder(7)]
	public string? IdToken { get; init; }
}
