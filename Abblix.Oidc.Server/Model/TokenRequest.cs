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

using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Utils.Json;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents a request to get various types of tokens
/// (e.g., access token, refresh token) from the authorization server.
/// </summary>
public record TokenRequest
{
	public static class Parameters
	{
		public const string GrantType = "grant_type";
		public const string Code = "code";
		public const string RedirectUri = "redirect_uri";
		public const string Resource = "resource";
		public const string RefreshToken = "refresh_token";
		public const string Scope = "scope";
		public const string Username = "username";
		public const string Password = "password";
		public const string CodeVerifier = "code_verifier";
	}

	/// <summary>
	/// The grant type of the token request, indicating the method being used to obtain the token.
	/// Common values include 'authorization_code', 'refresh_token', 'password', etc.
	/// </summary>
	[JsonPropertyName(Parameters.GrantType)]
	[Required]
	[AllowedValues(
		GrantTypes.AuthorizationCode,
		GrantTypes.RefreshToken,
		GrantTypes.Password,
		GrantTypes.Ciba,
		GrantTypes.Implicit,
		GrantTypes.ClientCredentials)]
	public string GrantType { get; set; } = default!;

	/// <summary>
	/// The authorization code received from the authorization server. This is used in the authorization code grant type.
	/// </summary>
	[JsonPropertyName(Parameters.Code)]
	public string? Code { get; set; }

	/// <summary>
	/// The redirect URI where the response will be sent. This must match the redirect URI registered with the authorization server.
	/// </summary>
	[JsonPropertyName(Parameters.RedirectUri)]
	public Uri? RedirectUri { get; set; }

	/// <summary>
	/// The resource for which the access token is being requested.
	/// This is optional and is used in scenarios such as OAuth 2.0 for APIs.
	/// </summary>
	/// <remarks>
	/// Defined in RFC 8707.
	/// </remarks>
	[JsonPropertyName(Parameters.Resource)]
	[JsonConverter(typeof(SingleOrArrayConverter<Uri>))]
	public Uri[]? Resources { get; set; }

	/// <summary>
	/// The refresh token used to obtain a new access token. Required for the refresh token grant type.
	/// </summary>
	[JsonPropertyName(Parameters.RefreshToken)]
	public string? RefreshToken { get; set; }

	/// <summary>
	/// The scope of the access request, expressed as a list of space-delimited, case-sensitive strings.
	/// </summary>
	[JsonPropertyName(Parameters.Scope)]
	[AllowedValues(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Phone, Scopes.OfflineAccess)]
	public string[] Scope { get; set; } = Array.Empty<string>();

	/// <summary>
	/// The username of the resource owner. Required for the password grant type.
	/// </summary>
	[JsonPropertyName(Parameters.Username)]
	public string? UserName { get; set; }

	/// <summary>
	/// The password of the resource owner. Required for the password grant type.
	/// </summary>
	[JsonPropertyName(Parameters.Password)]
	public string? Password { get; set; }

	/// <summary>
	/// The code verifier for the PKCE (Proof Key for Code Exchange) process.
	/// Required for public clients using the authorization code grant type.
	/// </summary>
	[JsonPropertyName(Parameters.CodeVerifier)]
	public string? CodeVerifier { get; set; }
}
