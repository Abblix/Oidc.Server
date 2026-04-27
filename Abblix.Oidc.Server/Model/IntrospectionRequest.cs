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
/// Parameters of an OAuth 2.0 token introspection request (RFC 7662 §2.1) sent to the
/// <c>introspection_endpoint</c>, used by protected resources to determine the active state and metadata
/// of a token. Client authentication is required and is supplied alongside this payload.
/// </summary>
public record IntrospectionRequest
{
	public static class Parameters
	{
		public const string Token = "token";
		public const string TokenTypeHint = "token_type_hint";
	}

	/// <summary>
	/// The <c>token</c> parameter (RFC 7662 §2.1): the token string for which the client is requesting
	/// introspection metadata. Required.
	/// </summary>
	[JsonPropertyName(Parameters.Token)]
	[Required]
	public string Token { get; set; } = null!;

	/// <summary>
	/// The optional <c>token_type_hint</c> (RFC 7662 §2.1) telling the server which token type to try first,
	/// for example <c>access_token</c> or <c>refresh_token</c>. The server may still inspect other token types.
	/// </summary>
	[JsonPropertyName(Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; }
}
