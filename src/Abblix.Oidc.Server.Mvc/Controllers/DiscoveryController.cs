// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net.Mime;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Mvc.Filters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using JsonWebKeySet = Abblix.Jwt.JsonWebKeySet;
using Abblix.Oidc.Server.Features.MultiTenancy;


namespace Abblix.Oidc.Server.Mvc.Controllers;

/// <summary>
/// The DiscoveryController handles requests for OpenID Connect Discovery, providing information about
/// the OpenID Provider's configuration. It supports endpoints for retrieving the provider's metadata and
/// its public key information.
/// </summary>
/// <remarks>
/// This controller implements the functionality described in the OpenID Connect Discovery 1.0 specification,
/// which enables clients to discover essential information about the OpenID Provider, such as its authorization
/// and token endpoints, supported scopes, response types, and more.
///
/// This facilitates clients in dynamically configuring themselves to communicate with the OpenID Provider.
/// For more details, refer to the OpenID Connect Discovery specification:
/// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html"/>.
/// </remarks>
// Discovery and JWKS are public, unauthenticated metadata, but they are still gated on HTTPS like the credential-
// bearing controllers: over cleartext a man-in-the-middle could rewrite the advertised endpoints or jwks_uri and
// steer clients onto attacker infrastructure. A host needing an ungated route (a health probe) adds its own.
[RequireHttpsUnlessHttpIssuer]
[RequireHost]
[RequireTenant]
[ReturnsOidcInvalidRequest]
[ReturnsLibraryRefusalStatus]
[SkipStatusCodePages]
[EnableCors(OidcConstants.CorsPolicyName)]
[OidcRouteValue]
[SuppressMessage("SonarLint", "S6967:ModelState.IsValid should be checked in controller actions", Justification = "ReturnsOidcInvalidRequest answers an invalid model state before any action runs")]
public sealed class DiscoveryController : ControllerBase
{
	/// <summary>
	/// Handles the request for the OpenID Provider Configuration Information. This endpoint
	/// returns crucial information about the OpenID Connect provider, such as the issuer,
	/// key discovery URIs, supported scopes, response types, and more, facilitating dynamic
	/// client configuration for OpenID Connect compliance.
	/// </summary>
	/// <remarks>
	/// The response adheres to the OpenID Connect Discovery specification, providing a
	/// standardized set of information necessary for clients to interact with the provider.
	/// </remarks>
	/// <param name="handler">The service responsible for building discovery metadata.</param>
	/// <param name="formatter">The service responsible for enriching the response with endpoint URLs.</param>
	/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
	/// <returns>A task that results in an action result containing the provider's configuration details
	/// in JSON format.</returns>
	[HttpGet]
	[ActionName(nameof(ConfigurationAsync))]
	[Produces(MediaTypeNames.Application.Json)]
	[ProducesResponseType(StatusCodes.Status200OK)]
	[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
	public async Task<ActionResult<Abblix.Oidc.Server.Model.ConfigurationResponse>> ConfigurationAsync(
		[FromServices] IConfigurationHandler handler,
		[FromServices] IConfigurationResponseFormatter formatter,
		[FromServices] ITenantAccessor tenantAccessor)
	{
		var response = await handler.HandleAsync(tenantAccessor.CurrentTenant());
		return await formatter.FormatResponseAsync(response);
	}

	/// <summary>
	/// Provides the public key information used by the OpenID Provider to sign tokens.
	/// This endpoint returns a JSON Web Key Set (JWKS) containing the public keys used by the provider.
	/// Clients can use these keys to verify the authenticity of identity tokens and access tokens issued by the provider.
	/// </summary>
	/// <param name="serviceKeysProvider">Provider for retrieving the service's public key information.</param>
	/// <param name="tenantAccessor">Names the tenant whose keys are published.</param>
	/// <param name="options">OIDC options; supplies the key-rollover propagation window used as the JWKS cache lifetime.</param>
	/// <param name="logger">Logger used to warn if a key still carrying private material is stripped before publication.</param>
	/// <returns>
	/// A JSON Web Key Set (JWKS) response in the form of <see cref="JsonWebKeySet"/> if the Keys endpoint is enabled,
	/// containing the public keys used by the provider. The response conforms to the application/json media type.
	/// If the Keys endpoint is disabled, a 404 Not Found response is returned.
	/// </returns>
	[HttpGet]
	[ActionName(nameof(KeysAsync))]
	public async Task<ActionResult<JsonWebKeySet>> KeysAsync(
		[FromServices] IAuthServiceKeysProvider serviceKeysProvider,
		[FromServices] ITenantAccessor tenantAccessor,
		[FromServices] IOptions<OidcOptions> options,
		[FromServices] ILogger<IAuthServiceKeysProvider> logger)
	{
		var keys = await serviceKeysProvider.GetPublishedKeysAsync(tenantAccessor.CurrentTenant(), logger);

		// The JWKS is public, cacheable metadata: advertise a lifetime equal to the key-rollover propagation
		// window (the deliberate exception to this controller's otherwise no-store metadata policy).
		Response.SetCacheableHeaders(options.Value.KeyRolloverPropagation);

		return new JsonWebKeySet(keys);
	}
}
