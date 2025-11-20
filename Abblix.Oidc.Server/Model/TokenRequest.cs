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
/// Represents a request to get various types of tokens (e.g., access token, refresh token) from
/// the authorization server. This is part of the OAuth 2.0 and OpenID Connect token exchange flow,
/// where clients can request tokens based on different grant types like 'authorization_code', 'refresh_token'
/// and others.
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
		public const string AuthenticationRequestId = "auth_req_id";
		public const string DeviceCode = "device_code";
	}

	/// <summary>
	/// The grant type of the token request, indicating the method being used to get the token.
	/// Common values include 'authorization_code', 'refresh_token', 'password', etc.
	/// </summary>
	[JsonPropertyName(Parameters.GrantType)]
	[Required]
	[AllowedValues(
		GrantTypes.AuthorizationCode,
		GrantTypes.RefreshToken,
		GrantTypes.Password,
		GrantTypes.Ciba,
		GrantTypes.DeviceAuthorization,
		GrantTypes.Implicit,
		GrantTypes.ClientCredentials)]
	public string GrantType { get; set; } = null!;

	/// <summary>
	/// The authorization code received from the authorization server.
	/// This is used in the authorization code grant type to exchange for an access token.
	/// </summary>
	[JsonPropertyName(Parameters.Code)]
	public string? Code { get; set; }

	/// <summary>
	/// The redirect URI where the response will be sent.
	/// This must match the redirect URI registered with the authorization server during the initial request.
	/// </summary>
	[JsonPropertyName(Parameters.RedirectUri)]
	public Uri? RedirectUri { get; set; }

	/// <summary>
	/// The resource URI(s) for which the access token is being requested.
	/// This parameter is optional and used in scenarios such as OAuth 2.0 for APIs
	/// to specify the resource(s) being accessed.
	/// </summary>
	/// <remarks>
	/// Defined in RFC 8707 as a way to express the resource(s) the client is requesting access to.
	/// </remarks>
	[JsonPropertyName(Parameters.Resource)]
	[JsonConverter(typeof(SingleOrArrayConverter<Uri>))]
	public Uri[]? Resources { get; set; }

	/// <summary>
	/// The refresh token used to get a new access token. Required when using the refresh token grant type.
	/// </summary>
	[JsonPropertyName(Parameters.RefreshToken)]
	public string? RefreshToken { get; set; }

	/// <summary>
	/// The scope of the access request, expressed as a space-separated list of case-sensitive strings.
	/// This defines the permissions or resources the client is requesting access to.
	/// </summary>
	[JsonPropertyName(Parameters.Scope)]
	public string[] Scope { get; set; } = [];

	/// <summary>
	/// The username of the resource owner, required when using the resource owner password credentials grant type.
	/// </summary>
	[JsonPropertyName(Parameters.Username)]
	public string? UserName { get; set; }

	/// <summary>
	/// The password of the resource owner, required when using the resource owner password credentials grant type.
	/// </summary>
	[JsonPropertyName(Parameters.Password)]
	public string? Password { get; set; }

	/// <summary>
	/// The code verifier used in the PKCE (Proof Key for Code Exchange) process.
	/// Required for public clients using the authorization code grant type to enhance security.
	/// </summary>
	[JsonPropertyName(Parameters.CodeVerifier)]
	public string? CodeVerifier { get; set; }

	/// <summary>
	/// The authentication request ID, used in CIBA (Client-Initiated Backchannel Authentication) flow.
	/// This identifier references a backchannel authentication request initiated by the client.
	/// </summary>
	[JsonPropertyName(Parameters.AuthenticationRequestId)]
	public string? AuthenticationRequestId { get; set; }

	/// <summary>
	/// The device code used in the Device Authorization Grant (RFC 8628) flow.
	/// This code is obtained from the device authorization endpoint and used to poll for tokens.
	/// </summary>
	[JsonPropertyName(Parameters.DeviceCode)]
	public string? DeviceCode { get; set; }
}
