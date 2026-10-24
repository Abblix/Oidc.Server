// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using ModelResponse = Abblix.Oidc.Server.Model.ConfigurationResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formats OpenID Connect configuration responses by enriching them with resolved MVC endpoint URLs.
/// </summary>
public class ConfigurationResponseFormatter(
	IOptionsSnapshot<OidcOptions> options,
	IOidcEndpointResolver endpointResolver,
	ISignedMetadataProvider signedMetadataProvider,
	ITenantAccessor tenantAccessor) : IConfigurationResponseFormatter
{
	/// <summary>
	/// Formats the configuration response by mapping metadata and adding endpoint URLs.
	/// </summary>
	/// <param name="response">Framework-agnostic configuration response with metadata.</param>
	/// <returns>An action result with the MVC-enriched configuration response including URLs.</returns>
	public async Task<ActionResult<ModelResponse>> FormatResponseAsync(EndpointResponse response)
	{
		var tokenEndpoint = Resolve(OidcEndpoints.Token, response.Issuer);
		var revocationEndpoint = Resolve(OidcEndpoints.Revocation, response.Issuer);
		var introspectionEndpoint = Resolve(OidcEndpoints.Introspection, response.Issuer);
		var userInfoEndpoint = Resolve(OidcEndpoints.UserInfo, response.Issuer);

		var mvcResponse = new ModelResponse
		{
			Issuer = response.Issuer.OriginalString,

			JwksUri = Resolve(OidcEndpoints.Keys, response.Issuer),

			AuthorizationEndpoint = Resolve(OidcEndpoints.Authorize, response.Issuer),
			UserInfoEndpoint = userInfoEndpoint,
			EndSessionEndpoint = Resolve(OidcEndpoints.EndSession, response.Issuer),
			CheckSessionIframe = Resolve(OidcEndpoints.CheckSession, response.Issuer),
			PushedAuthorizationRequestEndpoint = Resolve(OidcEndpoints.PushedAuthorizationRequest, response.Issuer),

			TokenEndpoint = tokenEndpoint,
			RevocationEndpoint = revocationEndpoint,
			IntrospectionEndpoint = introspectionEndpoint,

			RegistrationEndpoint = Resolve(OidcEndpoints.RegisterClient, response.Issuer),

			BackChannelAuthenticationEndpoint = Resolve(OidcEndpoints.BackChannelAuthentication, response.Issuer),

			DeviceAuthorizationEndpoint = Resolve(OidcEndpoints.DeviceAuthorization, response.Issuer),

			FrontChannelLogoutSupported = response.FrontChannelLogoutSupported,
			FrontChannelLogoutSessionSupported = response.FrontChannelLogoutSessionSupported,
			BackChannelLogoutSupported = response.BackChannelLogoutSupported,
			BackChannelLogoutSessionSupported = response.BackChannelLogoutSessionSupported,

			ClaimsParameterSupported = response.ClaimsParameterSupported,

			ScopesSupported = response.ScopesSupported,
			ClaimsSupported = response.ClaimsSupported,

			GrantTypesSupported = response.GrantTypesSupported,
			ResponseTypesSupported = response.ResponseTypesSupported,
			ResponseModesSupported = response.ResponseModesSupported,

			TokenEndpointAuthMethodsSupported = response.TokenEndpointAuthMethodsSupported,
			TokenEndpointAuthSigningAlgValuesSupported = response.TokenEndpointAuthSigningAlgValuesSupported,
			TlsClientCertificateBoundAccessTokens = response.TlsClientCertificateBoundAccessTokens,

			IdTokenSigningAlgValuesSupported = response.IdTokenSigningAlgValuesSupported,
			SubjectTypesSupported = response.SubjectTypesSupported,
			CodeChallengeMethodsSupported = response.CodeChallengeMethodsSupported,
			PromptValuesSupported = response.PromptValuesSupported,

			RequestParameterSupported = response.RequestParameterSupported,
			RequestObjectSigningAlgValuesSupported = response.RequestObjectSigningAlgValuesSupported,
			RequestObjectEncryptionAlgValuesSupported = response.RequestObjectEncryptionAlgValuesSupported,
			RequestObjectEncryptionEncValuesSupported = response.RequestObjectEncryptionEncValuesSupported,
			AuthorizationSigningAlgValuesSupported = response.AuthorizationSigningAlgValuesSupported,
			AuthorizationEncryptionAlgValuesSupported = response.AuthorizationEncryptionAlgValuesSupported,
			AuthorizationEncryptionEncValuesSupported = response.AuthorizationEncryptionEncValuesSupported,

			IntrospectionSigningAlgValuesSupported = response.IntrospectionSigningAlgValuesSupported,
			IntrospectionEncryptionAlgValuesSupported = response.IntrospectionEncryptionAlgValuesSupported,
			IntrospectionEncryptionEncValuesSupported = response.IntrospectionEncryptionEncValuesSupported,

			RequirePushedAuthorizationRequests = response.RequirePushedAuthorizationRequests,
			RequireSignedRequestObject = response.RequireSignedRequestObject,

			UserInfoSigningAlgValuesSupported = response.UserInfoSigningAlgValuesSupported,
			DpopSigningAlgValuesSupported = response.DpopSigningAlgValuesSupported,

			BackChannelTokenDeliveryModesSupported = response.BackChannelTokenDeliveryModesSupported,
			BackChannelAuthenticationRequestSigningAlgValuesSupported = response.BackChannelAuthenticationRequestSigningAlgValuesSupported,
			BackChannelUserCodeParameterSupported = response.BackChannelUserCodeParameterSupported,

			AcrValuesSupported = response.AcrValuesSupported,

			AuthorizationResponseIssParameterSupported = response.AuthorizationResponseIssParameterSupported,

			AuthorizationDetailsTypesSupported = response.AuthorizationDetailsTypesSupported,
		};

		mvcResponse = MtlsEndpointAliasing.WithMtlsAliases(mvcResponse, tenantAccessor.CurrentTenant().MtlsBaseUri);

		if (options.Value.Discovery.SignedMetadata)
		{
			mvcResponse = mvcResponse with { SignedMetadata = await signedMetadataProvider.SignAsync(mvcResponse) };
		}

		return mvcResponse;
	}

	/// <summary>
	/// Resolves the absolute URL of an endpoint if endpoint path discovery is enabled and the endpoint is active.
	/// </summary>
	/// <param name="endpoint">The endpoint flag that must be enabled for the URL to be resolved.</param>
	/// <param name="issuer">The issuer the document describes.</param>
	/// <returns>The absolute URI to the endpoint if discovery and endpoint are enabled; otherwise, null.</returns>
	private Uri? Resolve(OidcEndpoints endpoint, Uri issuer)
	{
		return options.Value.Discovery.AllowEndpointPathsDiscovery &&
		       options.Value.EnabledEndpoints.HasFlag(endpoint)
			? MtlsEndpointAliasing.OnIssuersHost(
				endpointResolver.Resolve(endpoint), issuer, tenantAccessor.CurrentTenant().MtlsBaseUri)
			: null;
	}
}
