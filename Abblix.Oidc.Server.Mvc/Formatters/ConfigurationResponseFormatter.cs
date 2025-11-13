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

using Abblix.Oidc.Server.Common.Configuration;
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
public sealed class ConfigurationResponseFormatter(
	IOptionsSnapshot<OidcOptions> options,
	IEndpointResolver endpointResolver) : IConfigurationResponseFormatter
{
	/// <summary>
	/// Formats the configuration response by mapping metadata and adding endpoint URLs.
	/// </summary>
	/// <param name="response">Framework-agnostic configuration response with metadata.</param>
	/// <returns>An action result with the MVC-enriched configuration response including URLs.</returns>
	public Task<ActionResult<ModelResponse>> FormatResponseAsync(EndpointResponse response)
	{
		var tokenEndpoint = Resolve<TokenController>(nameof(TokenController.TokenAsync), OidcEndpoints.Token);
		var revocationEndpoint = Resolve<TokenController>(nameof(TokenController.RevocationAsync), OidcEndpoints.Revocation);
		var introspectionEndpoint = Resolve<TokenController>(nameof(TokenController.IntrospectionAsync), OidcEndpoints.Introspection);
		var userInfoEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.UserInfoAsync), OidcEndpoints.UserInfo);

		var mvcResponse = new ModelResponse
		{
			Issuer = response.Issuer,

			JwksUri = Resolve<DiscoveryController>(nameof(DiscoveryController.KeysAsync), OidcEndpoints.Keys),

			AuthorizationEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.AuthorizeAsync), OidcEndpoints.Authorize),
			UserInfoEndpoint = userInfoEndpoint,
			EndSessionEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.EndSessionAsync), OidcEndpoints.EndSession),
			CheckSessionIframe = Resolve<AuthenticationController>(nameof(AuthenticationController.CheckSessionAsync), OidcEndpoints.CheckSession),
			PushedAuthorizationRequestEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.PushAuthorizeAsync), OidcEndpoints.PushedAuthorizationRequest),

			TokenEndpoint = tokenEndpoint,
			RevocationEndpoint = revocationEndpoint,
			IntrospectionEndpoint = introspectionEndpoint,

			RegistrationEndpoint = Resolve<ClientManagementController>(nameof(ClientManagementController.RegisterClientAsync), OidcEndpoints.RegisterClient),

			BackChannelAuthenticationEndpoint = Resolve<AuthenticationController>(nameof(AuthenticationController.BackChannelAuthenticationAsync), OidcEndpoints.BackChannelAuthentication),

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

			IdTokenSigningAlgValuesSupported = response.IdTokenSigningAlgValuesSupported,
			SubjectTypesSupported = response.SubjectTypesSupported,
			CodeChallengeMethodsSupported = response.CodeChallengeMethodsSupported,
			PromptValuesSupported = response.PromptValuesSupported,

			RequestParameterSupported = response.RequestParameterSupported,
			RequestObjectSigningAlgValuesSupported = response.RequestObjectSigningAlgValuesSupported,

			RequirePushedAuthorizationRequests = response.RequirePushedAuthorizationRequests,
			RequireSignedRequestObject = response.RequireSignedRequestObject,

			UserInfoSigningAlgValuesSupported = response.UserInfoSigningAlgValuesSupported,

			BackChannelTokenDeliveryModesSupported = response.BackChannelTokenDeliveryModesSupported,
			BackChannelAuthenticationRequestSigningAlgValuesSupported = response.BackChannelAuthenticationRequestSigningAlgValuesSupported,
			BackChannelUserCodeParameterSupported = response.BackChannelUserCodeParameterSupported,
		};

		// Add mTLS endpoint aliases if configured
		var mtlsOptions = options.Value.Discovery.MtlsEndpointAliases;
		var mtlsBaseUri = options.Value.Discovery.MtlsBaseUri;

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

		return Task.FromResult<ActionResult<ModelResponse>>(mvcResponse);
	}

	/// <summary>
	/// Resolves the absolute URL for a controller action if endpoint path discovery is enabled and the endpoint is active.
	/// </summary>
	/// <typeparam name="T">The controller type containing the action method.</typeparam>
	/// <param name="actionName">The name of the action method to resolve.</param>
	/// <param name="enablingFlag">The endpoint flag that must be enabled for the URL to be resolved.</param>
	/// <returns>The absolute URI to the endpoint if discovery and endpoint are enabled; otherwise, null.</returns>
	private Uri? Resolve<T>(string actionName, OidcEndpoints enablingFlag) where T : ControllerBase
	{
		return options.Value.Discovery.AllowEndpointPathsDiscovery &&
		       options.Value.EnabledEndpoints.HasFlag(enablingFlag)
			? endpointResolver.Resolve(MvcUtils.NameOf<T>(), MvcUtils.TrimAsync(actionName))
			: null;
	}

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
