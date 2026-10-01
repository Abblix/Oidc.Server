// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Features.EndpointResolving;
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
	IEndpointResolver endpointResolver,
	ISignedMetadataProvider signedMetadataProvider,
	IIssuerSettings issuerSettings) : IConfigurationResponseFormatter
{
	/// <summary>
	/// Formats the configuration response by mapping metadata and adding endpoint URLs.
	/// </summary>
	/// <param name="response">Framework-agnostic configuration response with metadata.</param>
	/// <returns>An action result with the MVC-enriched configuration response including URLs.</returns>
	public async Task<ActionResult<ModelResponse>> FormatResponseAsync(EndpointResponse response)
	{
		var tokenEndpoint = Resolve<TokenController>(nameof(TokenController.TokenAsync), OidcEndpoints.Token, response.Issuer);
		var revocationEndpoint = Resolve<TokenController>(nameof(TokenController.RevocationAsync), OidcEndpoints.Revocation, response.Issuer);
		var introspectionEndpoint = Resolve<TokenController>(nameof(TokenController.IntrospectionAsync), OidcEndpoints.Introspection, response.Issuer);
		var userInfoEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.UserInfoAsync), OidcEndpoints.UserInfo, response.Issuer);

		var mvcResponse = new ModelResponse
		{
			Issuer = response.Issuer,

			JwksUri = Resolve<DiscoveryController>(nameof(DiscoveryController.KeysAsync), OidcEndpoints.Keys, response.Issuer),

			AuthorizationEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.AuthorizeAsync), OidcEndpoints.Authorize, response.Issuer),
			UserInfoEndpoint = userInfoEndpoint,
			EndSessionEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.EndSessionAsync), OidcEndpoints.EndSession, response.Issuer),
			CheckSessionIframe = Resolve<AuthenticationController>(nameof(AuthenticationController.CheckSessionAsync), OidcEndpoints.CheckSession, response.Issuer),
			PushedAuthorizationRequestEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.PushAuthorizeAsync), OidcEndpoints.PushedAuthorizationRequest, response.Issuer),

			TokenEndpoint = tokenEndpoint,
			RevocationEndpoint = revocationEndpoint,
			IntrospectionEndpoint = introspectionEndpoint,

			RegistrationEndpoint = Resolve<ClientManagementController>(nameof(ClientManagementController.RegisterClientAsync), OidcEndpoints.RegisterClient, response.Issuer),

			BackChannelAuthenticationEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.BackChannelAuthenticationAsync), OidcEndpoints.BackChannelAuthentication, response.Issuer),

			DeviceAuthorizationEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.DeviceAuthorizationAsync), OidcEndpoints.DeviceAuthorization, response.Issuer),

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

		// Add mTLS endpoint aliases if configured
		var mtlsOptions = options.Value.Discovery.MtlsEndpointAliases;
		var mtlsBaseUri = issuerSettings.MtlsBaseUri;

		if (mtlsOptions != null || mtlsBaseUri != null)
		{
			mvcResponse = mvcResponse with
			{
				MtlsEndpointAliases = new Abblix.Oidc.Server.Model.MtlsAliases
				{
					TokenEndpoint = mtlsOptions?.TokenEndpoint ?? Rebase(tokenEndpoint, mtlsBaseUri),
					RevocationEndpoint = mtlsOptions?.RevocationEndpoint ?? Rebase(revocationEndpoint, mtlsBaseUri),
					IntrospectionEndpoint = mtlsOptions?.IntrospectionEndpoint ?? Rebase(introspectionEndpoint, mtlsBaseUri),
					UserInfoEndpoint = mtlsOptions?.UserInfoEndpoint ?? Rebase(userInfoEndpoint, mtlsBaseUri),
				}
			};
		}

		if (options.Value.Discovery.SignedMetadata)
		{
			mvcResponse = mvcResponse with { SignedMetadata = await signedMetadataProvider.SignAsync(mvcResponse) };
		}

		return mvcResponse;
	}

	/// <summary>
	/// Resolves the absolute URL for a controller action if endpoint path discovery is enabled and the endpoint is active.
	/// </summary>
	/// <typeparam name="T">The controller type containing the action method.</typeparam>
	/// <param name="actionName">The name of the action method to resolve.</param>
	/// <param name="enablingFlag">The endpoint flag that must be enabled for the URL to be resolved.</param>
	/// <param name="issuer">The issuer the document describes.</param>
	/// <returns>The absolute URI to the endpoint if discovery and endpoint are enabled; otherwise, null.</returns>
	private Uri? Resolve<T>(string actionName, OidcEndpoints enablingFlag, string issuer) where T : ControllerBase
	{
		return options.Value.Discovery.AllowEndpointPathsDiscovery &&
		       options.Value.EnabledEndpoints.HasFlag(enablingFlag)
			? OnIssuersHost(endpointResolver.Resolve(MvcUtils.NameOf<T>(), MvcUtils.TrimAsync(actionName)), issuer)
			: null;
	}

	/// <summary>
	/// An endpoint resolved on the issuer's mutual-TLS host, where the document was fetched, moved to the issuer's
	/// own host: a client without a certificate follows the ordinary endpoints, and only the aliases may name the host
	/// that demands one.
	/// </summary>
	/// <remarks>
	/// The host is compared as a tenant is resolved by it, so whatever request reaches the tenant on its mutual-TLS host
	/// is answered so. A server without tenants whose mutual-TLS host differs from its ordinary one only by port
	/// therefore names the ordinary endpoints on the issuer's host on either.
	/// </remarks>
	private Uri? OnIssuersHost(Uri? endpoint, string issuer)
		=> endpoint is not null &&
		   issuerSettings.MtlsBaseUri is { } mtlsBaseUri &&
		   SameHost(endpoint, mtlsBaseUri)
			? Rebase(endpoint, new Uri(new Uri(issuer).GetLeftPart(UriPartial.Authority)))
			: endpoint;

#pragma warning disable ABXMT001
	private static bool SameHost(Uri endpoint, Uri mtlsBaseUri)
		=> TenantHost.Normalize(endpoint.Host) == TenantHost.Normalize(mtlsBaseUri.Host);
#pragma warning restore ABXMT001

	/// <summary>
	/// Rebases an original URI to use a different base URI, preserving the original's path.
	/// Used to generate mTLS endpoint aliases with alternative base URLs.
	/// </summary>
	/// <param name="original">The original URI to rebase.</param>
	/// <param name="baseUri">The new base URI to use (scheme, host, port, and optionally base path).</param>
	/// <returns>A new URI combining the base URI with the original's path, or null if either parameter is null.</returns>
	private static Uri? Rebase(Uri? original, Uri? baseUri)
	{
		if (baseUri == null)
			return original;

		if (original == null)
			return null;

		var basePath = baseUri.AbsolutePath.TrimEnd('/');
		var origPath = original.AbsolutePath.TrimStart('/');

		var ub = new UriBuilder(baseUri)
		{
			Path = string.IsNullOrEmpty(basePath) || basePath == "/"
				? $"/{origPath}"
				: $"{basePath}/{origPath}",
		};
		return ub.Uri;
	}
}
