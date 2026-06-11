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
	/// <summary>
	/// Wire-level parameter names accepted at the token endpoint per RFC 6749 §4, RFC 7636 (PKCE),
	/// RFC 7523 (JWT Bearer), RFC 8628 (Device Authorization Grant), RFC 8707 (Resource Indicators),
	/// and OpenID Connect CIBA Core.
	/// </summary>
	public static class Parameters
	{
		/// <summary>The <c>grant_type</c> token request parameter selecting the grant flow
		/// (<c>authorization_code</c>, <c>refresh_token</c>, <c>password</c>, etc.).</summary>
		public const string GrantType = "grant_type";
		/// <summary>The <c>code</c> token request parameter carrying the authorization code obtained
		/// from the authorization endpoint.</summary>
		public const string Code = "code";

		/// <summary>The <c>redirect_uri</c> token request parameter; must match the value supplied at
		/// the authorization endpoint.</summary>
		public const string RedirectUri = "redirect_uri";

		/// <summary>The <c>resource</c> token request parameter (RFC 8707) listing target resources for
		/// the issued access token.</summary>
		public const string Resource = "resource";

		/// <summary>The <c>refresh_token</c> token request parameter carrying the refresh token to be
		/// exchanged for a new access token.</summary>
		public const string RefreshToken = "refresh_token";

		/// <summary>The <c>scope</c> token request parameter listing requested scopes.</summary>
		public const string Scope = "scope";

		/// <summary>The <c>username</c> token request parameter for the resource-owner password
		/// credentials grant.</summary>
		public const string Username = "username";

		/// <summary>The <c>password</c> token request parameter for the resource-owner password
		/// credentials grant.</summary>
		public const string Password = "password";

		/// <summary>The <c>code_verifier</c> PKCE token request parameter (RFC 7636).</summary>
		public const string CodeVerifier = "code_verifier";

		/// <summary>The <c>auth_req_id</c> token request parameter identifying a CIBA backchannel
		/// authentication request.</summary>
		public const string AuthenticationRequestId = "auth_req_id";

		/// <summary>The <c>assertion</c> token request parameter carrying a JWT bearer assertion
		/// (RFC 7523).</summary>
		public const string Assertion = "assertion";

		/// <summary>The <c>device_code</c> token request parameter for the Device Authorization Grant
		/// (RFC 8628).</summary>
		public const string DeviceCode = "device_code";

		/// <summary>The <c>subject_token</c> Token Exchange request parameter carrying the security
		/// token being exchanged (RFC 8693 §2.1).</summary>
		public const string SubjectToken = "subject_token";

		/// <summary>The <c>subject_token_type</c> Token Exchange request parameter identifying the
		/// format of <c>subject_token</c> (RFC 8693 §2.1).</summary>
		public const string SubjectTokenType = "subject_token_type";

		/// <summary>The <c>actor_token</c> Token Exchange request parameter carrying a security token
		/// representing the acting party in delegation flows (RFC 8693 §2.1).</summary>
		public const string ActorToken = "actor_token";

		/// <summary>The <c>actor_token_type</c> Token Exchange request parameter identifying the
		/// format of <c>actor_token</c> (RFC 8693 §2.1).</summary>
		public const string ActorTokenType = "actor_token_type";

		/// <summary>The <c>requested_token_type</c> Token Exchange request parameter naming the
		/// type of token the client would like to receive in the response (RFC 8693 §2.1).</summary>
		public const string RequestedTokenType = "requested_token_type";

		/// <summary>The <c>audience</c> Token Exchange request parameter naming the logical name(s)
		/// of the relying party the requested token is intended for (RFC 8693 §2.1).</summary>
		public const string Audience = "audience";
	}

	/// <summary>
	/// The grant type of the token request, indicating the method being used to get the token.
	/// Common values include 'authorization_code', 'refresh_token', 'password', etc.
	/// </summary>
	/// <remarks>
	/// Deliberately not constrained by a declarative value list: grant handlers are an extensible,
	/// host-configured set, and the composite grant handler rejects an unregistered grant with the
	/// protocol-level unsupported grant type error.
	/// </remarks>
	[JsonPropertyName(Parameters.GrantType)]
	[Required]
	public string GrantType { get; set; } = default!;

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
	/// The JWT assertion used in the JWT Bearer grant type per RFC 7523.
	/// This contains a signed JWT with claims about the resource owner and is used to request an access token.
	/// </summary>
	[JsonPropertyName(Parameters.Assertion)]
	public string? Assertion { get; set; }

	/// <summary>
	/// The device code used in the Device Authorization Grant (RFC 8628) flow.
	/// This code is obtained from the device authorization endpoint and used to poll for tokens.
	/// </summary>
	[JsonPropertyName(Parameters.DeviceCode)]
	public string? DeviceCode { get; set; }

	/// <summary>
	/// RFC 8693 §2.1 <c>subject_token</c> -- the security token being exchanged. Required for
	/// <see cref="GrantTypes.TokenExchange"/>.
	/// </summary>
	[JsonPropertyName(Parameters.SubjectToken)]
	public string? SubjectToken { get; set; }

	/// <summary>
	/// RFC 8693 §2.1 <c>subject_token_type</c> -- identifier for the format of <see cref="SubjectToken"/>,
	/// one of <see cref="TokenExchangeTokenTypes"/>. Required for <see cref="GrantTypes.TokenExchange"/>.
	/// </summary>
	[JsonPropertyName(Parameters.SubjectTokenType)]
	public string? SubjectTokenType { get; set; }

	/// <summary>
	/// RFC 8693 §2.1 <c>actor_token</c> -- security token representing the acting party in delegation
	/// flows. Optional. When present, <see cref="ActorTokenType"/> MUST also be present.
	/// </summary>
	[JsonPropertyName(Parameters.ActorToken)]
	public string? ActorToken { get; set; }

	/// <summary>
	/// RFC 8693 §2.1 <c>actor_token_type</c> -- identifier for the format of <see cref="ActorToken"/>,
	/// one of <see cref="TokenExchangeTokenTypes"/>. Required when <see cref="ActorToken"/> is present.
	/// </summary>
	[JsonPropertyName(Parameters.ActorTokenType)]
	public string? ActorTokenType { get; set; }

	/// <summary>
	/// RFC 8693 §2.1 <c>requested_token_type</c> -- identifier of the token type the client would like
	/// the AS to issue, one of <see cref="TokenExchangeTokenTypes"/>. Optional; defaults to
	/// <see cref="TokenExchangeTokenTypes.AccessToken"/>.
	/// </summary>
	[JsonPropertyName(Parameters.RequestedTokenType)]
	public string? RequestedTokenType { get; set; }

	/// <summary>
	/// RFC 8693 §2.1 <c>audience</c> -- logical name(s) of the relying party for which the requested
	/// token is intended. Distinct from <see cref="Resources"/> (RFC 8707 absolute URIs); audience is
	/// a free-form identifier.
	/// </summary>
	[JsonPropertyName(Parameters.Audience)]
	public string[]? Audiences { get; set; }
}
