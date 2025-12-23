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

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
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
	IAuthenticationCompletionHandler cibaCompletionHandler,
	IAcrMetadataProvider acrMetadata) : IConfigurationHandler
{
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

		RequirePushedAuthorizationRequests = options.Value.RequirePushedAuthorizationRequests,
		RequireSignedRequestObject = options.Value.RequireSignedRequestObject,

		TokenEndpointAuthMethodsSupported = clientAuthenticator.ClientAuthenticationMethodsSupported,
		TokenEndpointAuthSigningAlgValuesSupported = jwtAlgorithms.SigningAlgorithmsSupported,
		IdTokenSigningAlgValuesSupported = jwtAlgorithms.SignedResponseAlgorithmsSupported,
		UserInfoSigningAlgValuesSupported = jwtAlgorithms.SignedResponseAlgorithmsSupported,

		BackChannelAuthenticationRequestSigningAlgValuesSupported = jwtAlgorithms.SigningAlgorithmsSupported,
		BackChannelTokenDeliveryModesSupported = cibaCompletionHandler.TokenDeliveryModesSupported,
		BackChannelUserCodeParameterSupported = options.Value.BackChannelAuthentication.UserCodeParameterSupported,

		AcrValuesSupported = acrMetadata.AcrValuesSupported,
	});
}
