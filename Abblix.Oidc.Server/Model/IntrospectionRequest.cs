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
	public string Token { get; set; } = default!;

	/// <summary>
	/// A hint about the type of the token submitted for introspection.
	/// This property is optional and can be used to optimize the introspection process.
	/// The value can be standardized token type values such as "access_token" or "refresh_token".
	/// </summary>
	[JsonPropertyName(Parameters.TokenTypeHint)]
	public string? TokenTypeHint { get; set; }
}
