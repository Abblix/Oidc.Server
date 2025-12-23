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

namespace Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;

/// <summary>
/// Framework-agnostic OpenID Connect discovery metadata response.
/// Contains provider capabilities, supported features, and cryptographic algorithms,
/// but excludes endpoint URLs which are framework-specific.
/// </summary>
public record ConfigurationResponse
{
	/// <summary>
	/// The issuer identifier, which uniquely identifies the OpenID Provider.
	/// </summary>
	public string Issuer { init; get; } = null!;

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
	/// </summary>
	public IEnumerable<string> ScopesSupported { init; get; } = null!;

	/// <summary>
	/// Lists the claims supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> ClaimsSupported { init; get; } = null!;

	/// <summary>
	/// Lists the grant types supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> GrantTypesSupported { init; get; } = null!;

	/// <summary>
	/// Lists the response types supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> ResponseTypesSupported { init; get; } = null!;

	/// <summary>
	/// Lists the response modes supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> ResponseModesSupported { init; get; } = null!;

	/// <summary>
	/// Lists the token endpoint authentication methods supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> TokenEndpointAuthMethodsSupported { init; get; } = null!;

	/// <summary>
	/// Lists the signing algorithms supported for authenticating clients at the token endpoint.
	/// </summary>
	public IEnumerable<string>? TokenEndpointAuthSigningAlgValuesSupported { get; init; }

	/// <summary>
	/// Lists the ID token signing algorithm values supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> IdTokenSigningAlgValuesSupported { init; get; } = null!;

	/// <summary>
	/// Lists the subject types supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> SubjectTypesSupported { init; get; } = null!;

	/// <summary>
	/// Lists the code challenge methods supported for PKCE.
	/// </summary>
	public IEnumerable<string> CodeChallengeMethodsSupported { init; get; } = null!;

	/// <summary>
	/// Indicates whether the OpenID Provider supports the use of the request parameter.
	/// </summary>
	public bool RequestParameterSupported { init; get; }

	/// <summary>
	/// Lists the prompt values supported by the OpenID Provider.
	/// </summary>
	public IEnumerable<string> PromptValuesSupported { init; get; } = null!;

	/// <summary>
	/// Specifies the signing algorithms supported for user information endpoints.
	/// </summary>
	public IEnumerable<string>? UserInfoSigningAlgValuesSupported { init; get; }

	/// <summary>
	/// Specifies the signing algorithms supported for request objects.
	/// </summary>
	public IEnumerable<string>? RequestObjectSigningAlgValuesSupported { init; get; }

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
}
