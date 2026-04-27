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
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Carries the OAuth 2.0 client authentication material common to back-channel endpoints (token,
/// introspection, revocation): credentials passed in the request body per RFC 6749 §2.3.1, JWT-based
/// client assertions per RFC 7521/7523, and the mTLS client certificate per RFC 8705.
/// Concrete request DTOs typically expose these values alongside their endpoint-specific parameters.
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
	/// The HTTP <c>Authorization</c> header from the inbound request, captured for transport-level
	/// authentication schemes such as <c>Basic</c> (client_secret_basic) or <c>Bearer</c>. Not serialized.
	/// </summary>
	[JsonIgnore]
	public AuthenticationHeaderValue? AuthorizationHeader { get; set; }

	/// <summary>
	/// The OAuth 2.0 <c>client_id</c> identifying the registered client (RFC 6749 §2.3.1).
	/// May be <c>null</c> when the client is identified solely by an Authorization header or a client assertion.
	/// </summary>
	[JsonPropertyName(Parameters.ClientId)]
	public string? ClientId { get; set; }

	/// <summary>
	/// The OAuth 2.0 <c>client_secret</c> presented in the request body for the
	/// <c>client_secret_post</c> authentication method (RFC 6749 §2.3.1).
	/// </summary>
	[JsonPropertyName(Parameters.ClientSecret)]
	public string? ClientSecret { get; set; }

	/// <summary>
	/// The <c>client_assertion_type</c>, which for JWT bearer client assertions equals
	/// <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c> per RFC 7521 §4.2 / RFC 7523 §2.2.
	/// </summary>
	[JsonPropertyName(Parameters.ClientAssertionType)]
	public string? ClientAssertionType { get; set; }

	/// <summary>
	/// The <c>client_assertion</c>: a signed JWT used to authenticate the client via
	/// <c>private_key_jwt</c> or <c>client_secret_jwt</c> (RFC 7523 §2.2, OIDC Core §9).
	/// </summary>
    [JsonPropertyName(Parameters.ClientAssertion)]
    public string? ClientAssertion { get; set; }

    /// <summary>
    /// The client X.509 certificate presented via mutual TLS (mTLS) at the transport layer
    /// or forwarded by a trusted reverse proxy. Used for RFC 8705 client authentication and
    /// for certificate-bound access tokens.
    /// </summary>
    public X509Certificate2? ClientCertificate { get; set; }
}
