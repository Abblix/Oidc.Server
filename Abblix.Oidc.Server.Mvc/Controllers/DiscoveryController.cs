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

using System.Net.Mime;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Mvc.Filters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using JsonWebKeySet = Abblix.Jwt.JsonWebKeySet;


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
[ApiController]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[SkipStatusCodePages]
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
	/// <returns>A task that results in an action result containing the provider's configuration details
	/// in JSON format.</returns>
	[HttpGet(Path.Configuration)]
	[Produces(MediaTypeNames.Application.Json)]
	[ProducesResponseType(StatusCodes.Status200OK)]
	[EnabledBy(OidcEndpoints.Configuration)]
	public async Task<ActionResult<Abblix.Oidc.Server.Model.ConfigurationResponse>> ConfigurationAsync(
		[FromServices] IConfigurationHandler handler,
		[FromServices] IConfigurationResponseFormatter formatter)
	{
		var response = await handler.HandleAsync();
		return await formatter.FormatResponseAsync(response);
	}

	/// <summary>
	/// Provides the public key information used by the OpenID Provider to sign tokens.
	/// This endpoint returns a JSON Web Key Set (JWKS) containing the public keys used by the provider.
	/// Clients can use these keys to verify the authenticity of identity tokens and access tokens issued by the provider.
	/// </summary>
	/// <param name="serviceKeysProvider">Provider for retrieving the service's public key information.</param>
	/// <returns>
	/// A JSON Web Key Set (JWKS) response in the form of <see cref="JsonWebKeySet"/> if the Keys endpoint is enabled,
	/// containing the public keys used by the provider. The response conforms to the application/json media type.
	/// If the Keys endpoint is disabled, a 404 Not Found response is returned.
	/// </returns>
	[HttpGet(Path.Keys)]
	[EnabledBy(OidcEndpoints.Keys)]
	public async Task<ActionResult<JsonWebKeySet>> KeysAsync(
		[FromServices] IAuthServiceKeysProvider serviceKeysProvider)
	{
		var keys = await serviceKeysProvider.GetSigningKeys().ToArrayAsync();
		return new JsonWebKeySet(keys);
	}
}
