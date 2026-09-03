// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Abblix.Oidc.Server.DeclarativeBinding;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Model;

/// <summary>
/// Carries the OAuth 2.0 client authentication material common to back-channel endpoints (token,
/// introspection, revocation): credentials passed in the request body per RFC 6749 section 2.3.1, JWT-based
/// client assertions per RFC 7521/7523, and the mTLS client certificate per RFC 8705.
/// Concrete request DTOs typically expose these values alongside their endpoint-specific parameters.
/// </summary>
public record ClientRequest
{
	/// <summary>
	/// Wire-level parameter names for OAuth 2.0 client authentication material common to back-channel
	/// endpoints (RFC 6749 section 2.3.1, RFC 7521/7523 client assertions, OIDC Core section 9).
	/// </summary>
	public static class Parameters
	{
		/// <summary>The <c>client_id</c> request parameter identifying the registered client.</summary>
		public const string ClientId = "client_id";

		/// <summary>The <c>client_secret</c> request parameter presented in the body for the
		/// <c>client_secret_post</c> authentication method.</summary>
		public const string ClientSecret = "client_secret";

		/// <summary>The <c>client_assertion_type</c> request parameter naming the assertion format
		/// (e.g. <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c>).</summary>
		public const string ClientAssertionType = "client_assertion_type";

		/// <summary>The <c>client_assertion</c> request parameter carrying the signed JWT client
		/// assertion.</summary>
		public const string ClientAssertion = "client_assertion";
	}

	/// <summary>
	/// The HTTP <c>Authorization</c> header from the inbound request, captured for transport-level
	/// authentication schemes such as <c>Basic</c> (client_secret_basic) or <c>Bearer</c>. Not serialized.
	/// </summary>
	[JsonIgnore]
	[AuthorizationHeader]
	public AuthenticationHeaderValue? AuthorizationHeader { get; set; }

	/// <summary>
	/// The OAuth 2.0 <c>client_id</c> identifying the registered client (RFC 6749 section 2.3.1).
	/// May be <c>null</c> when the client is identified solely by an Authorization header or a client assertion.
	/// </summary>
	[JsonPropertyName(Parameters.ClientId)]
	public string? ClientId { get; set; }

	/// <summary>
	/// The OAuth 2.0 <c>client_secret</c> presented in the request body for the
	/// <c>client_secret_post</c> authentication method (RFC 6749 section 2.3.1).
	/// </summary>
	[JsonPropertyName(Parameters.ClientSecret)]
	public string? ClientSecret { get; set; }

	/// <summary>
	/// The <c>client_assertion_type</c>, which for JWT bearer client assertions equals
	/// <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c> per RFC 7521 section 4.2 / RFC 7523 section 2.2.
	/// </summary>
	[JsonPropertyName(Parameters.ClientAssertionType)]
	public string? ClientAssertionType { get; set; }

	/// <summary>
	/// The <c>client_assertion</c>: a signed JWT used to authenticate the client via
	/// <c>private_key_jwt</c> or <c>client_secret_jwt</c> (RFC 7523 section 2.2, OIDC Core section 9).
	/// </summary>
    [JsonPropertyName(Parameters.ClientAssertion)]
    public string? ClientAssertion { get; set; }

    /// <summary>
    /// The client X.509 certificate presented via mutual TLS (mTLS) at the transport layer
    /// or forwarded by a trusted reverse proxy. Used for RFC 8705 client authentication and
    /// for certificate-bound access tokens.
    /// </summary>
    [JsonIgnore]
    [ClientCertificate]
    public X509Certificate2? ClientCertificate { get; set; }

    /// <summary>
    /// The compact-form DPoP proof JWT taken from the inbound request's <c>DPoP</c> header
    /// per RFC 9449 section 4.1. Travels alongside <see cref="AuthorizationHeader"/> and
    /// <see cref="ClientCertificate"/> as transport-level material so the core layer stays
    /// ASP.NET-Core-free; the MVC binder lifts it from the header. <c>null</c> when no
    /// proof was presented.
    /// </summary>
    [JsonIgnore]
    [RequestHeader(HttpRequestHeaders.DPoP)]
    public string? DPoPProof { get; set; }
}
