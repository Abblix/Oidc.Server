// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt;
using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Microsoft.Extensions.Options;

using ConfigurationResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;

namespace Abblix.Oidc.Server.Endpoints.Configuration;

/// <summary>
/// Handles OpenID Connect discovery configuration requests by building metadata response.
/// Returns framework-agnostic discovery metadata without endpoint URLs.
/// </summary>
[SuppressMessage("SonarQube", "S107:Methods should not have too many parameters",
	Justification = "Configuration handler legitimately requires multiple specialized metadata providers to assemble comprehensive OIDC discovery document")]
public sealed class ConfigurationHandler(
	IOptionsSnapshot<OidcOptions> options,
	ITenantCatalog catalog,
	ILogoutNotifier logoutNotifier,
	IClientAuthenticator clientAuthenticator,
	IAuthorizationMetadataProvider authorizationMetadata,
	IScopesAndClaimsProvider scopesAndClaims,
	IJwtAlgorithmsProvider jwtAlgorithms,
	IAuthServiceKeysProvider serviceKeys,
	IEnumerable<IAuthenticationCompletionHandler> cibaCompletionHandlers,
	IAcrMetadataProvider acrMetadata,
	Features.RichAuthorizationRequests.IAuthorizationDetailsMetadataProvider authorizationDetailsMetadata) : IConfigurationHandler
{
	// CIBA metadata is advertised only when the CIBA feature is opted in (AddBackChannelAuthentication), the sole
	// registrar of IAuthenticationCompletionHandler. Resolved from a collection so discovery - an always-on
	// endpoint - still constructs under ValidateOnBuild when CIBA is off; null means CIBA is disabled, so the
	// backchannel discovery fields are omitted rather than advertised.
	private readonly IAuthenticationCompletionHandler? cibaCompletionHandler = cibaCompletionHandlers.FirstOrDefault();

	/// <summary>
	/// Handles the configuration request by building discovery metadata.
	/// </summary>
	/// <returns>Configuration response with metadata but without resolved endpoint URLs.</returns>
	public async Task<ConfigurationResponse> HandleAsync(TenantDefinition tenant)
	{
		var requestObjectEncryption = await RequestObjectEncryptionAsync(tenant);

		return new ConfigurationResponse
		{
			Issuer = Licensed(tenant),

			FrontChannelLogoutSupported = logoutNotifier.FrontChannelLogoutSupported,
			FrontChannelLogoutSessionSupported = logoutNotifier.FrontChannelLogoutSessionSupported,
			BackChannelLogoutSupported = logoutNotifier.BackChannelLogoutSupported,
			BackChannelLogoutSessionSupported = logoutNotifier.BackChannelLogoutSessionSupported,

			ScopesSupported = scopesAndClaims.ScopesSupported(tenant),
			ClaimsSupported = scopesAndClaims.ClaimsSupported(tenant),
			GrantTypesSupported = scopesAndClaims.GrantTypesSupported,
			SubjectTypesSupported = scopesAndClaims.SubjectTypesSupported(tenant),

			ClaimsParameterSupported = authorizationMetadata.ClaimsParameterSupported,
			ResponseTypesSupported = AdmittedResponseTypes(tenant, authorizationMetadata.ResponseTypesSupported),
			ResponseModesSupported = authorizationMetadata.ResponseModesSupported,

			PromptValuesSupported = authorizationMetadata.PromptValuesSupported,
			CodeChallengeMethodsSupported = authorizationMetadata.CodeChallengeMethodsSupported,
			RequestParameterSupported = authorizationMetadata.RequestParameterSupported,
			RequestObjectSigningAlgValuesSupported = authorizationMetadata.RequestParameterSupported
				? Signing(tenant, jwtAlgorithms.SigningAlgorithmsSupported)
				: null,
			// A content encryption algorithm is of no use to a client with no key management algorithm to pair it with
			RequestObjectEncryptionAlgValuesSupported = requestObjectEncryption,
			RequestObjectEncryptionEncValuesSupported = requestObjectEncryption is null
				? null
				: jwtAlgorithms.RequestObjectEncryptionEncValuesSupported,

			// JARM (JWT Secured Authorization Response Mode) is always available - a client opts in per request
			// by selecting a *.jwt response mode - so the supported algorithms are advertised unconditionally.
			AuthorizationSigningAlgValuesSupported = Signing(tenant, jwtAlgorithms.AuthorizationSigningAlgValuesSupported),
			AuthorizationEncryptionAlgValuesSupported =
				KeyManagement(tenant, jwtAlgorithms.AuthorizationEncryptionAlgValuesSupported),
			AuthorizationEncryptionEncValuesSupported = jwtAlgorithms.AuthorizationEncryptionEncValuesSupported,

			// RFC 9701 JWT introspection responses are always available - a client opts in per request via Accept and
			// its registered introspection_signed_response_alg - so the supported algorithms are advertised unconditionally.
			IntrospectionSigningAlgValuesSupported =
				SigningOrPlain(tenant, jwtAlgorithms.IntrospectionSigningAlgValuesSupported),
			IntrospectionEncryptionAlgValuesSupported =
				KeyManagement(tenant, jwtAlgorithms.IntrospectionEncryptionAlgValuesSupported),
			IntrospectionEncryptionEncValuesSupported = jwtAlgorithms.IntrospectionEncryptionEncValuesSupported,

			RequirePushedAuthorizationRequests = options.Value.RequirePushedAuthorizationRequests,
			RequireSignedRequestObject = options.Value.RequireSignedRequestObject,

			TokenEndpointAuthMethodsSupported = clientAuthenticator.ClientAuthenticationMethodsSupported,

			// RFC 8705 section 3.3: advertise certificate-bound access tokens only when a mutual-TLS client
			// authentication method is available - the server then both issues bound tokens and
			// enforces the binding at its protected resources (MtlsUserInfoValidator).
			TlsClientCertificateBoundAccessTokens = clientAuthenticator.ClientAuthenticationMethodsSupported.Any(
				method => method is ClientAuthenticationMethods.TlsClientAuth
					or ClientAuthenticationMethods.SelfSignedTlsClientAuth)
				? true
				: null,

			TokenEndpointAuthSigningAlgValuesSupported =
				Signing(tenant, jwtAlgorithms.TokenEndpointAuthSigningAlgValuesSupported),
			IdTokenSigningAlgValuesSupported = Signing(tenant, jwtAlgorithms.SignedResponseAlgorithmsSupported),
			UserInfoSigningAlgValuesSupported = SigningOrPlain(tenant, jwtAlgorithms.SignedResponseAlgorithmsSupported),
			// RFC 9449 section 5.1: the metadata is there "to signal support for DPoP in general", so a tenant whose
			// profile refuses DPoP (FAPI 1.0 Part 2 section 8.2) does not carry it
			DpopSigningAlgValuesSupported = SecurityProfileRequirements.For(tenant, client: null).RequireCertificateBoundTokens
				? null
				: Signing(tenant, jwtAlgorithms.DpopSigningAlgorithmsSupported),

			BackChannelAuthenticationRequestSigningAlgValuesSupported = cibaCompletionHandler is null
				? null
				: Signing(tenant, jwtAlgorithms.BackChannelAuthenticationRequestSigningAlgValuesSupported),
			BackChannelTokenDeliveryModesSupported = cibaCompletionHandler?.TokenDeliveryModesSupported,
			BackChannelUserCodeParameterSupported =
				cibaCompletionHandler is null ? null : options.Value.BackChannelAuthentication.UserCodeParameterSupported,

			AcrValuesSupported = acrMetadata.AcrValuesSupported(tenant),

			AuthorizationResponseIssParameterSupported = authorizationMetadata.AuthorizationResponseIssParameterSupported,

			AuthorizationDetailsTypesSupported = authorizationDetailsMetadata.SupportedTypes,
		};
	}

	/// <summary>
	/// The key management algorithms a client can encrypt a request object to <paramref name="tenant"/> under: those
	/// the tenant's profile admits that one of its own published encryption keys can be used with. A key declaring
	/// its algorithm opens only that one (RFC 8725 section 3.1), so the registered algorithms alone would promise a
	/// client algorithms its request object is refused under. Null when there is none, or no request object is
	/// accepted at all: OpenID Connect Discovery 1.0 section 4.2, "Claims with zero elements MUST be omitted from the
	/// response".
	/// </summary>
	private async Task<string[]?> RequestObjectEncryptionAsync(TenantDefinition tenant)
	{
		if (!authorizationMetadata.RequestParameterSupported)
			return null;

		var algorithms = KeyManagement(
				tenant,
				await serviceKeys.GetInboundKeyManagementAlgorithmsAsync(
					tenant,
					jwtAlgorithms.RequestObjectEncryptionAlgValuesSupported))
			.ToArray();

		return algorithms.Length > 0 ? algorithms : null;
	}

	/// <summary>
	/// The response types of <paramref name="responseTypes"/> the tenant's profile admits at the authorization endpoint.
	/// FAPI 2.0 Security Profile section 5.3.2.2: "authorization servers shall require the value of response_type
	/// described in [RFC6749] to be code". FAPI 1.0 Part 2 section 5.2.2: the server "shall require the response_type
	/// value code id_token, or the response_type value code in conjunction with the response_mode value jwt". The
	/// tenant's profile binds every client it serves, so a value it refuses is one this authorization server does not
	/// support, and OpenID Connect Discovery 1.0 section 3 and RFC 8414 section 2 list only the values it supports.
	/// </summary>
	private static IEnumerable<string> AdmittedResponseTypes(TenantDefinition tenant, IEnumerable<string> responseTypes)
	{
		var profile = SecurityProfileRequirements.For(tenant, client: null);
		return responseTypes.Where(responseType => Admits(profile, responseType));
	}

	/// <summary>
	/// Whether <paramref name="profile"/> admits <paramref name="responseType"/>, one value of the list the authorization
	/// endpoint metadata builds, whose parts stand in their canonical order.
	/// </summary>
	private static bool Admits(SecurityProfileRequirements profile, string responseType)
	{
		if (responseType == ResponseTypes.Code)
			return true;

		if (profile.RequireCodeResponseTypeOnly)
			return false;

		// A response nothing signs is refused where the profile requires a signed one: code id_token is the one
		// response type besides code whose ID token signs it
		return profile.SignedAuthorizationResponseModes is null
			|| responseType == $"{ResponseTypes.Code} {ResponseTypes.IdToken}";
	}

	/// <summary>
	/// The signature algorithms of <paramref name="algorithms"/> the tenant's profile admits: FAPI 1.0 Part 2 section
	/// 8.6, FAPI 2.0 section 5.4.1. A client registering what the document lists is then registered with an algorithm
	/// it can use.
	/// </summary>
	private static IEnumerable<string> Signing(TenantDefinition tenant, IEnumerable<string> algorithms)
		=> algorithms.Where(SecurityProfileRequirements.For(tenant, client: null).PermitsSigningAlgorithm);

	/// <summary>
	/// As <see cref="Signing"/>, keeping <c>none</c>, which for a userinfo or introspection response means plain JSON
	/// rather than an unsigned JWS.
	/// </summary>
	private static IEnumerable<string> SigningOrPlain(TenantDefinition tenant, IEnumerable<string> algorithms)
	{
		var profile = SecurityProfileRequirements.For(tenant, client: null);
		return algorithms.Where(algorithm => algorithm == SigningAlgorithms.None || profile.PermitsSigningAlgorithm(algorithm));
	}

	/// <summary>
	/// The key management algorithms of <paramref name="algorithms"/> the tenant's profile admits: FAPI 1.0 Part 2
	/// section 8.6.1, FAPI 2.0 section 5.4.1 by RFC 8725 section 3.2.
	/// </summary>
	private static IEnumerable<string> KeyManagement(TenantDefinition tenant, IEnumerable<string> algorithms)
		=> algorithms.Where(SecurityProfileRequirements.For(tenant, client: null).PermitsKeyManagementAlgorithm);

	/// <summary>
	/// The issuer of <paramref name="tenant"/>, once the license has counted it as written.
	/// </summary>
	private Uri Licensed(TenantDefinition tenant)
	{
		LicenseChecker.CheckIssuer(tenant.Issuer.OriginalString, tenant, catalog);
		return tenant.Issuer;
	}
}
