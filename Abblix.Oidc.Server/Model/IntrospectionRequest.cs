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
/// Represents a request for OAuth 2.0 token introspection, allowing clients to query the authorization server
/// about the state and details of a token.
/// Inherits from <see cref="ClientRequest"/>.
/// </summary>
public record IntrospectionRequest
{
	public static class Parameters
	{
		public const string Token = "token";
		public const string TokenTypeHint = "token_type_hint";
	}

	/// <summary>
	/// The token that the client wants to introspect.
	/// This property is and should contain the string value of the token.
	/// </summary>
	[JsonPropertyName(Parameters.Token)]
	[Required]
	public string Token { get; set; } = null!;

	/// <summary>
	/// A hint about the type of the token submitted for introspection.
	/// This property is optional and can be used to optimize the introspection process.
	/// The value can be standardized token type values such as "access_token" or "refresh_token".
	/// </summary>
	[JsonPropertyName(Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; }
}
