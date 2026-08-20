// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.Issuer;
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
	IIssuerProvider issuerProvider,
	ILogoutNotifier logoutNotifier,
	IClientAuthenticator clientAuthenticator,
	IAuthorizationMetadataProvider authorizationMetadata,
	IScopesAndClaimsProvider scopesAndClaims,
	IJwtAlgorithmsProvider jwtAlgorithms,
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
	public Task<ConfigurationResponse> HandleAsync() => Task.FromResult(new ConfigurationResponse
	{
		Issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer()),

		FrontChannelLogoutSupported = logoutNotifier.FrontChannelLogoutSupported,
		FrontChannelLogoutSessionSupported = logoutNotifier.FrontChannelLogoutSessionSupported,
		BackChannelLogoutSupported = logoutNotifier.BackChannelLogoutSupported,
		BackChannelLogoutSessionSupported = logoutNotifier.BackChannelLogoutSessionSupported,

		ScopesSupported = scopesAndClaims.ScopesSupported,
		ClaimsSupported = scopesAndClaims.ClaimsSupported,
		GrantTypesSupported = scopesAndClaims.GrantTypesSupported,
		SubjectTypesSupported = scopesAndClaims.SubjectTypesSupported,

		ClaimsParameterSupported = authorizationMetadata.ClaimsParameterSupported,
		ResponseTypesSupported = authorizationMetadata.ResponseTypesSupported,
		ResponseModesSupported = authorizationMetadata.ResponseModesSupported,

		PromptValuesSupported = authorizationMetadata.PromptValuesSupported,
		CodeChallengeMethodsSupported = authorizationMetadata.CodeChallengeMethodsSupported,
		RequestParameterSupported = authorizationMetadata.RequestParameterSupported,
		RequestObjectSigningAlgValuesSupported = authorizationMetadata.RequestParameterSupported
			? jwtAlgorithms.SigningAlgorithmsSupported
			: null,
		RequestObjectEncryptionAlgValuesSupported = authorizationMetadata.RequestParameterSupported
			? jwtAlgorithms.RequestObjectEncryptionAlgValuesSupported
			: null,
		RequestObjectEncryptionEncValuesSupported = authorizationMetadata.RequestParameterSupported
			? jwtAlgorithms.RequestObjectEncryptionEncValuesSupported
			: null,

		// JARM (JWT Secured Authorization Response Mode) is always available - a client opts in per request
		// by selecting a *.jwt response mode - so the supported algorithms are advertised unconditionally.
		AuthorizationSigningAlgValuesSupported = jwtAlgorithms.AuthorizationSigningAlgValuesSupported,
		AuthorizationEncryptionAlgValuesSupported = jwtAlgorithms.AuthorizationEncryptionAlgValuesSupported,
		AuthorizationEncryptionEncValuesSupported = jwtAlgorithms.AuthorizationEncryptionEncValuesSupported,

		// RFC 9701 JWT introspection responses are always available - a client opts in per request via Accept and
		// its registered introspection_signed_response_alg - so the supported algorithms are advertised unconditionally.
		IntrospectionSigningAlgValuesSupported = jwtAlgorithms.IntrospectionSigningAlgValuesSupported,
		IntrospectionEncryptionAlgValuesSupported = jwtAlgorithms.IntrospectionEncryptionAlgValuesSupported,
		IntrospectionEncryptionEncValuesSupported = jwtAlgorithms.IntrospectionEncryptionEncValuesSupported,

		RequirePushedAuthorizationRequests = options.Value.RequirePushedAuthorizationRequests,
		RequireSignedRequestObject = options.Value.RequireSignedRequestObject,

		TokenEndpointAuthMethodsSupported = clientAuthenticator.ClientAuthenticationMethodsSupported,

		// RFC 8705 §3.3: advertise certificate-bound access tokens only when a mutual-TLS client
		// authentication method is available - the server then both issues bound tokens and
		// enforces the binding at its protected resources (MtlsUserInfoValidator).
		TlsClientCertificateBoundAccessTokens = clientAuthenticator.ClientAuthenticationMethodsSupported.Any(
			method => method is ClientAuthenticationMethods.TlsClientAuth
				or ClientAuthenticationMethods.SelfSignedTlsClientAuth)
			? true
			: null,

		TokenEndpointAuthSigningAlgValuesSupported = jwtAlgorithms.TokenEndpointAuthSigningAlgValuesSupported,
		IdTokenSigningAlgValuesSupported = jwtAlgorithms.SignedResponseAlgorithmsSupported,
		UserInfoSigningAlgValuesSupported = jwtAlgorithms.SignedResponseAlgorithmsSupported,
		DpopSigningAlgValuesSupported = jwtAlgorithms.DpopSigningAlgorithmsSupported,

		BackChannelAuthenticationRequestSigningAlgValuesSupported =
			cibaCompletionHandler is null ? null : jwtAlgorithms.BackChannelAuthenticationRequestSigningAlgValuesSupported,
		BackChannelTokenDeliveryModesSupported = cibaCompletionHandler?.TokenDeliveryModesSupported,
		BackChannelUserCodeParameterSupported =
			cibaCompletionHandler is null ? null : options.Value.BackChannelAuthentication.UserCodeParameterSupported,

		AcrValuesSupported = acrMetadata.AcrValuesSupported,

		AuthorizationResponseIssParameterSupported = authorizationMetadata.AuthorizationResponseIssParameterSupported,

		AuthorizationDetailsTypesSupported = authorizationDetailsMetadata.SupportedTypes,
	});
}
