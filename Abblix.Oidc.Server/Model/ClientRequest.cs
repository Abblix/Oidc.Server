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
