// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using System.Net.Mime;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Mvc.Attributes;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Oidc.Server.Mvc.Model;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using TokenResponse = Abblix.Oidc.Server.Mvc.Model.TokenResponse;

namespace Abblix.Oidc.Server.Mvc.Controllers;

/// <summary>
/// Manages OAuth 2.0 and OpenID Connect token-related endpoints, including token issuance, revocation, and introspection.
/// Serves as the primary interface between clients and the authorization server for managing tokens' lifecycle.
/// </summary>
[ApiController]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[SkipStatusCodePages]
[RequireHttps]
public class TokenController : ControllerBase
{
    /// <summary>
    /// Processes token issuance requests by evaluating authorization grants and issuing access, ID and refresh tokens
    /// accordingly.
    /// </summary>
    /// <param name="handler">The service responsible for handling token issuance logic.</param>
    /// <param name="formatter">The service tasked with formatting the token issuance response.</param>
    /// <param name="tokenRequest">Details of the token request, including grant type and required parameters.</param>
    /// <param name="clientRequest">Contextual information about the client making the request.</param>
    /// <returns>A task that results in an action containing the token response, formatted as per OIDC specifications.
    /// </returns>
    /// <remarks>
    /// This endpoint is central to the OAuth 2.0 and OpenID Connect framework, facilitating the secure issuance
    /// of tokens to authenticated clients.
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint">
    /// OpenID Connect Token Endpoint Documentation
    /// </see>
    /// </remarks>
    [HttpGetOrPost(Path.Token)]
    //[Consumes(MediaTypes.FormUrlEncoded)]
    [Produces(MediaTypeNames.Application.Json)]
    [EnableCors(OidcConstants.CorsPolicyName)]
    public async Task<ActionResult<TokenResponse>> TokenAsync(
        [FromServices] ITokenHandler handler,
        [FromServices] ITokenResponseFormatter formatter,
        [FromQueryOrForm] TokenRequest tokenRequest,
        [FromQueryOrForm] ClientRequest clientRequest)
    {
        var mappedTokenRequest = tokenRequest.Map();
        var mappedClientRequest = clientRequest.Map();
        var response = await handler.HandleAsync(mappedTokenRequest, mappedClientRequest);
        return await formatter.FormatResponseAsync(mappedTokenRequest, response);
    }

    /// <summary>
    /// Facilitates the revocation of issued tokens, enhancing security by allowing clients to invalidate tokens
    /// no longer needed or potentially compromised.
    /// </summary>
    /// <param name="handler">The service responsible for processing token revocation requests.</param>
    /// <param name="formatter">The service responsible for formatting the revocation response.</param>
    /// <param name="revocationRequest">Details of the revocation request, including the token to be revoked.</param>
    /// <param name="clientRequest">Additional contextual information about the client making the revocation request.</param>
    /// <returns>A task that results in an action indicating the outcome of the revocation process.</returns>
    /// <remarks>
    /// Adheres to the OAuth 2.0 Token Revocation standard, allowing clients to manage the lifecycle of their tokens
    /// securely.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7009#section-2">OAuth 2.0 Token Revocation Documentation</see>
    /// </remarks>
    [HttpPost(Path.Revocation)]
    [Consumes(MediaTypes.FormUrlEncoded)]
    [EnableCors(OidcConstants.CorsPolicyName)]
    public async Task<ActionResult> RevocationAsync(
        [FromServices] IRevocationHandler handler,
        [FromServices] IRevocationResponseFormatter formatter,
        [FromForm] RevocationRequest revocationRequest,
        [FromForm] ClientRequest clientRequest)
    {
        var mappedRevocationRequest = revocationRequest.Map();
        var mappedClientRequest = clientRequest.Map();
        var response = await handler.HandleAsync(mappedRevocationRequest, mappedClientRequest);
        return await formatter.FormatResponseAsync(mappedRevocationRequest, response);
    }

    /// <summary>
    /// Allows clients to query the state of a specific token, verifying its validity, active status, and other relevant
    /// metadata.
    /// </summary>
    /// <param name="handler">The service responsible for validating and processing token introspection requests.</param>
    /// <param name="formatter">The service responsible for formatting the introspection response with detailed token
    /// information.</param>
    /// <param name="introspectionRequest">Details of the introspection request, including the token to be introspected.
    /// </param>
    /// <param name="clientRequest">Additional contextual information about the client making the introspection request.
    /// </param>
    /// <returns>A task that results in an action providing detailed information about the state of the queried token.
    /// </returns>
    /// <remarks>
    /// Implements the OAuth 2.0 Token Introspection specification, allowing clients to verify the status of tokens in
    /// a secure manner.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2">OAuth 2.0 Token Introspection Documentation</see>
    /// </remarks>
    [HttpPost(Path.Introspection)]
    [Consumes(MediaTypes.FormUrlEncoded)]
    public async Task<ActionResult> IntrospectionAsync(
        [FromServices] IIntrospectionHandler handler,
        [FromServices] IIntrospectionResponseFormatter formatter,
        [FromForm] IntrospectionRequest introspectionRequest,
        [FromForm] ClientRequest clientRequest)
    {
        var mappedIntrospectionRequest = introspectionRequest.Map();
        var mappedClientRequest = clientRequest.Map();
        var response = await handler.HandleAsync(mappedIntrospectionRequest, mappedClientRequest);
        return await formatter.FormatResponseAsync(mappedIntrospectionRequest, response);
    }
}
