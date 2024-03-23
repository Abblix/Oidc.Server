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

using System.Net.Http.Headers;
using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Represents an abstract model of a request made by a client via a server-to-server call.
/// This record includes all headers and properties that can be used for authentication in various ways.
/// </summary>
public record ClientRequest
{
	public static class Parameters
	{
		public const string ClientId = "client_id";
		public const string ClientSecret = "client_secret";
		public const string ClientAssertionType = "client_assertion_type";
		public const string ClientAssertion = "client_assertion";
	}

	/// <summary>
	/// The authorization header used for client authentication. This typically contains credentials like bearer tokens.
	/// </summary>
	public AuthenticationHeaderValue? AuthorizationHeader { get; set; }

	/// <summary>
	/// The client identifier as registered in the authorization server.
	/// It is unique to the client and used to identify it in the authentication process.
	/// </summary>
	[JsonPropertyName(Parameters.ClientId)]
	public string? ClientId { get; set; }

	/// <summary>
	/// The client secret, a confidential string used to authenticate the client with the authorization server.
	/// </summary>
	[JsonPropertyName(Parameters.ClientSecret)]
	public string? ClientSecret { get; set; }

	/// <summary>
	/// The assertion type for the client authentication. This is typically used with JWT bearer tokens.
	/// </summary>
	[JsonPropertyName(Parameters.ClientAssertionType)]
	public string? ClientAssertionType { get; set; }

	/// <summary>
	/// The client assertion, often a JWT, used as a credential to authenticate the client to the authorization server.
	/// </summary>
	[JsonPropertyName(Parameters.ClientAssertion)]
	public string? ClientAssertion { get; set; }
}
