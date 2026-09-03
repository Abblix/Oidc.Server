// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Framework-agnostic OpenID Connect discovery metadata response.
/// Contains provider capabilities, supported features, and cryptographic algorithms,
/// but excludes endpoint URLs which are framework-specific.
/// </summary>
/// <remarks>
/// Each member's C# nullability mirrors what OpenID Connect Discovery 1.0 section 3 says about the corresponding
/// metadata field, so that the compiler asks of a handler exactly what the specification asks of a provider.
/// The four fields that section marks REQUIRED are <c>required</c> here; everything else is nullable, because
/// RECOMMENDED and OPTIONAL fields are legitimately absent and <c>null</c> is how this type says "not stated"
/// (the wire model omits nulls entirely). Several of the optional ones carry a default that applies precisely
/// when the field is omitted, so omission is an answer rather than a gap: <c>grant_types_supported</c> defaults
/// to authorization code and implicit, <c>response_modes_supported</c> to query and fragment, and
/// <c>token_endpoint_auth_methods_supported</c> to client_secret_basic.
/// Before this, all eleven were declared non-nullable with a null-forgiving initialiser, which swore they were
/// always present while nothing enforced it. A custom <see cref="IConfigurationHandler"/> that left one out
/// produced no error at all: the null travelled into the wire model, whose null-omitting serialisation dropped
/// the field, so a discovery document could silently ship without a REQUIRED member and answer 200.
/// </remarks>
public record ConfigurationResponse
{
	/// <summary>
	/// The issuer identifier, which uniquely identifies the OpenID Provider.
	/// REQUIRED by OpenID Connect Discovery 1.0 section 3.
	/// </summary>
	public required string Issuer { init; get; }

	/// <summary>
	/// Indicates whether the OpenID Provider supports front channel logout.
	/// </summary>
	public bool? FrontChannelLogoutSupported { init; get; }

	/// <summary>
	/// Indicates whether the OpenID Provider supports session management for front channel logout.
	/// </summary>
	public bool? FrontChannelLogoutSessionSupported { init; get; }

	/// <summary>
	/// Indicates whether the OpenID Provider supports back channel logout.
	/// </summary>
	public bool? BackChannelLogoutSupported { init; get; }

	/// <summary>
	/// Indicates whether the OpenID Provider supports session management for back channel logout.
	/// </summary>
	public bool? BackChannelLogoutSessionSupported { init; get; }

	/// <summary>
	/// Indicates whether the OpenID Provider supports the use of the claims parameter.
	/// </summary>
	public bool? ClaimsParameterSupported { init; get; }

	/// <summary>
	/// Lists the scopes supported by the OpenID Provider.
	/// RECOMMENDED by OpenID Connect Discovery 1.0 section 3.
	/// </summary>
	public IEnumerable<string>? ScopesSupported { init; get; }

	/// <summary>
	/// Lists the claims supported by the OpenID Provider.
	/// RECOMMENDED by OpenID Connect Discovery 1.0 section 3.
	/// </summary>
	public IEnumerable<string>? ClaimsSupported { init; get; }

	/// <summary>
	/// Lists the grant types supported by the OpenID Provider.
	/// OPTIONAL per OpenID Connect Discovery 1.0 section 3, which defines the omitted case as
	/// authorization code and implicit.
	/// </summary>
	public IEnumerable<string>? GrantTypesSupported { init; get; }

	/// <summary>
	/// Lists the response types supported by the OpenID Provider.
	/// REQUIRED by OpenID Connect Discovery 1.0 section 3.
	/// </summary>
	public required IEnumerable<string> ResponseTypesSupported { init; get; }

	/// <summary>
	/// Lists the response modes supported by the OpenID Provider.
	/// OPTIONAL per OpenID Connect Discovery 1.0 section 3, which defines the omitted case as query and fragment.
	/// </summary>
	public IEnumerable<string>? ResponseModesSupported { init; get; }

	/// <summary>
	/// Lists the token endpoint authentication methods supported by the OpenID Provider.
	/// OPTIONAL per OpenID Connect Discovery 1.0 section 3, which defines the omitted case as client_secret_basic.
	/// </summary>
	public IEnumerable<string>? TokenEndpointAuthMethodsSupported { init; get; }

	/// <summary>
	/// Lists the signing algorithms supported for authenticating clients at the token endpoint.
	/// </summary>
	public IEnumerable<string>? TokenEndpointAuthSigningAlgValuesSupported { get; init; }

	/// <summary>
	/// Lists the ID token signing algorithm values supported by the OpenID Provider.
	/// REQUIRED by OpenID Connect Discovery 1.0 section 3.
	/// </summary>
	public required IEnumerable<string> IdTokenSigningAlgValuesSupported { init; get; }

	/// <summary>
	/// Lists the subject types supported by the OpenID Provider.
	/// REQUIRED by OpenID Connect Discovery 1.0 section 3.
	/// </summary>
	public required IEnumerable<string> SubjectTypesSupported { init; get; }

	/// <summary>
	/// Lists the code challenge methods supported for PKCE.
	/// OPTIONAL per RFC 8414 section 2.
	/// </summary>
	public IEnumerable<string>? CodeChallengeMethodsSupported { init; get; }

	/// <summary>
	/// Indicates whether the OpenID Provider supports the use of the request parameter.
	/// </summary>
	public bool RequestParameterSupported { init; get; }

	/// <summary>
	/// Lists the prompt values supported by the OpenID Provider.
	/// OPTIONAL per Initiating User Registration via OpenID Connect 1.0 section 4.2, which defines the field
	/// outside the core metadata list. That section also states the obligation that follows from stating it at
	/// all: a provider listing this element must list every prompt value it supports, not only <c>create</c>.
	/// </summary>
	public IEnumerable<string>? PromptValuesSupported { init; get; }

	/// <summary>
	/// Specifies the signing algorithms supported for user information endpoints.
	/// </summary>
	public IEnumerable<string>? UserInfoSigningAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWS signing algorithms accepted on inbound DPoP proofs per
	/// RFC 9449 section 5.1 (<c>dpop_signing_alg_values_supported</c>): the intersection of
	/// the algorithms the AS validator can verify with the static DPoP-compatible
	/// whitelist.
	/// </summary>
	public IEnumerable<string>? DpopSigningAlgValuesSupported { init; get; }

	/// <summary>
	/// Indicates support for mutual-TLS client certificate-bound access tokens
	/// (<c>tls_client_certificate_bound_access_tokens</c>, RFC 8705 section 3.3). <c>true</c> when
	/// the provider both issues such tokens and enforces the binding at its protected
	/// resources; <c>null</c> (omitted) otherwise.
	/// </summary>
	public bool? TlsClientCertificateBoundAccessTokens { init; get; }

	/// <summary>
	/// Specifies the signing algorithms supported for request objects.
	/// </summary>
	public IEnumerable<string>? RequestObjectSigningAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWE key-management algorithms (the <c>alg</c> values) supported for encrypted request objects.
	/// </summary>
	public IEnumerable<string>? RequestObjectEncryptionAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWE content-encryption algorithms (the <c>enc</c> values) supported for encrypted request objects.
	/// </summary>
	public IEnumerable<string>? RequestObjectEncryptionEncValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWS algorithms supported for signing JARM authorization responses (JARM section 4).
	/// </summary>
	public IEnumerable<string>? AuthorizationSigningAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWE key-management algorithms (the <c>alg</c> values) supported for encrypting JARM
	/// authorization responses (JARM section 4).
	/// </summary>
	public IEnumerable<string>? AuthorizationEncryptionAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWE content-encryption algorithms (the <c>enc</c> values) supported for encrypting JARM
	/// authorization responses (JARM section 4).
	/// </summary>
	public IEnumerable<string>? AuthorizationEncryptionEncValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWS algorithms supported for signing JWT introspection responses (RFC 9701 section 7).
	/// </summary>
	public IEnumerable<string>? IntrospectionSigningAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWE key-management algorithms (the <c>alg</c> values) supported for encrypting JWT
	/// introspection responses (RFC 9701 section 7).
	/// </summary>
	public IEnumerable<string>? IntrospectionEncryptionAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the JWE content-encryption algorithms (the <c>enc</c> values) supported for encrypting JWT
	/// introspection responses (RFC 9701 section 7).
	/// </summary>
	public IEnumerable<string>? IntrospectionEncryptionEncValuesSupported { init; get; }

	/// <summary>
	/// Indicates whether the OpenID Provider requires clients to use Pushed Authorization Requests (PAR) only.
	/// </summary>
	public bool? RequirePushedAuthorizationRequests { get; set; }

	/// <summary>
	/// Indicates whether the OpenID Provider mandates that all request objects must be signed.
	/// </summary>
	public bool? RequireSignedRequestObject { init; get; }

	/// <summary>
	/// Lists the supported backchannel token delivery modes for CIBA.
	/// </summary>
	public IEnumerable<string>? BackChannelTokenDeliveryModesSupported { get; init; }

	/// <summary>
	/// Lists the supported signing algorithms for backchannel authentication requests.
	/// </summary>
	public IEnumerable<string>? BackChannelAuthenticationRequestSigningAlgValuesSupported { get; init; }

	/// <summary>
	/// Indicates whether the OpenID Provider supports the backchannel user code parameter for CIBA.
	/// </summary>
	public bool? BackChannelUserCodeParameterSupported { get; init; }

	/// <summary>
	/// Lists the ACR (Authentication Context Class Reference) values supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string>? AcrValuesSupported { get; init; }

	/// <summary>
	/// Indicates whether the server includes the <c>iss</c> parameter in authorization responses per RFC 9207.
	/// </summary>
	public bool? AuthorizationResponseIssParameterSupported { get; init; }

	/// <summary>
	/// RFC 9396 section 10: the authorization-detail <c>type</c> values this server's host has
	/// registered validators for. Sourced from the same keyed-DI registry that request-time
	/// dispatch uses; emitted as <c>authorization_details_types_supported</c> on the wire,
	/// or omitted when null (no per-type validators registered).
	/// </summary>
	public IEnumerable<string>? AuthorizationDetailsTypesSupported { get; init; }
}
