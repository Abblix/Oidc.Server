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


namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Parameters of an OAuth 2.0 token revocation request (RFC 7009 §2.1) sent to the
/// <c>revocation_endpoint</c>. Client authentication is required and is supplied alongside this payload.
/// </summary>
public record RevocationRequest
{
	public static class Parameters
	{
		public const string Token = "token";
		public const string TokenTypeHint = "token_type_hint";
	}

	/// <summary>
	/// The <c>token</c> parameter (RFC 7009 §2.1): the access token or refresh token string the client
	/// is asking the authorization server to revoke. Required.
	/// </summary>
	[JsonPropertyName(Parameters.Token)]
	[Required]
	public string Token { get; set; } = null!;

	/// <summary>
	/// The optional <c>token_type_hint</c> (RFC 7009 §2.1) advising whether <see cref="Token"/> is an
	/// <c>access_token</c> or <c>refresh_token</c>, allowing the server to look it up faster.
	/// </summary>
	[JsonPropertyName(Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; }
}
