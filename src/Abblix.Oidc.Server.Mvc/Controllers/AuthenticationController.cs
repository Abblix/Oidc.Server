// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Net.Mime;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Mvc.Model;
using Abblix.Oidc.Server.Mvc.Attributes;
using Abblix.Oidc.Server.Mvc.Filters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Controllers;

/// <summary>
/// Handles authentication-related processes in the context of OpenID Connect and OAuth2 protocols.
/// This controller manages user authorization, provides user information, handles end-session requests,
/// and checks session statuses.
/// </summary>
/// <remarks>
/// This controller serves as the core component for managing user authentication and session control
/// in an OpenID Connect compliant manner. It includes endpoints for initiating user authorization,
/// retrieving authenticated user information, managing user logout processes, and checking the status
/// of user sessions for OIDC compliance.
/// </remarks>
[ApiController]
[ReturnsOidcInvalidRequest]
[ReturnsLibraryRefusalStatus]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[SkipStatusCodePages]
[RequireHttps]
[SuppressMessage("SonarLint", "S6934:Route attributes should be specified on the controller", Justification = "All action methods have explicit route templates; class-level route is redundant")]
public sealed class AuthenticationController : ControllerBase
{
    /// <summary>
    /// Handles requests to the authorization endpoint, performing user authentication and getting consent for
    /// requested scopes.
    /// </summary>
    /// <param name="handler">The handler responsible for processing authorization requests.</param>
    /// <param name="formatter">The formatter used to generate a response for the authorization request.</param>
    /// <param name="request">The authorization request details received from the client.</param>
    /// <returns>A task that returns an action result containing
    /// the authorization response.</returns>
    /// <remarks>
    /// This endpoint is a key component of the OpenID Connect flow, initiating user authentication and
    /// consent for access to their information.
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint">
    /// OpenID Connect Authorization Endpoint Documentation
    /// </see>
    /// </remarks>
    [HttpGetOrPost(Path.Authorize)]
    //[Consumes(MediaTypes.FormUrlEncoded)]
    [Produces(MediaTypeNames.Text.Html, MediaTypeNames.Application.Json)]
    [EnabledBy(OidcEndpoints.Authorize)]
    public async Task<ActionResult<Core.AuthorizationResponse>> AuthorizeAsync(
        [FromServices] IAuthorizationHandler handler,
        [FromServices] IAuthorizationResponseFormatter formatter,
        [FromQueryOrForm] AuthorizationRequest request)
    {
        Core.AuthorizationRequest coreAuthorizationRequest = request;
        var response = await handler.HandleAsync(coreAuthorizationRequest);
        return await formatter.FormatResponseAsync(coreAuthorizationRequest, response);
    }

    /// <summary>
    /// Processes requests to the userinfo endpoint, returning claims about the authenticated user based on
    /// the provided access token.
    /// </summary>
    /// <param name="handler">The handler responsible for processing userinfo requests.</param>
    /// <param name="formatter">The formatter used to generate a response with user claims.</param>
    /// <param name="userInfoRequest">The userinfo request containing the access token.</param>
    /// <param name="clientRequest">Additional request information provided by the client.</param>
    /// <returns>A task that returns an action result containing
    /// the userinfo response.</returns>
    /// <remarks>
    /// This endpoint provides claims about the authenticated user, conforming to the
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">
    /// OpenID Connect UserInfo Endpoint Documentation
    /// </see>
    /// </remarks>
    [HttpGetOrPost(Path.UserInfo)]
    [EnableCors(OidcConstants.CorsPolicyName)]
    [EnabledBy(OidcEndpoints.UserInfo)]
    public async Task<ActionResult> UserInfoAsync(
        [FromServices] IUserInfoHandler handler,
        [FromServices] IUserInfoResponseFormatter formatter,
        [FromQueryOrForm] UserInfoRequest userInfoRequest,
        [FromForm] ClientRequest clientRequest)
    {
        Core.UserInfoRequest coreUserInfoRequest = userInfoRequest;
        var response = await handler.HandleAsync(coreUserInfoRequest, clientRequest);
        return await formatter.FormatResponseAsync(coreUserInfoRequest, response);
    }

    /// <summary>
    /// Facilitates the logout process by handling requests to the end session endpoint,
    /// allowing clients to terminate the user's session.
    /// </summary>
    /// <param name="handler">The handler responsible for processing end session requests.</param>
    /// <param name="formatter">The formatter used to generate a response for the end session request.</param>
    /// <param name="request">The end session request details received from the client.</param>
    /// <returns>A task that returns an action result for
    /// the end session process.</returns>
    /// <remarks>
    /// This endpoint supports the RP-Initiated Logout functionality, enabling clients to initiate
    /// logout procedures compliant with OpenID Connect.
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">
    /// OpenID Connect EndSession Endpoint Documentation
    /// </see>
    /// </remarks>
    [HttpGetOrPost(Path.EndSession)]
    //[Consumes(MediaTypes.FormUrlEncoded, IsOptional = true)]
    [Produces(MediaTypeNames.Text.Html, MediaTypeNames.Application.Json)]
    [EnableCors(OidcConstants.CorsPolicyName)]
    [EnabledBy(OidcEndpoints.EndSession)]
    public async Task<ActionResult> EndSessionAsync(
        [FromServices] IEndSessionHandler handler,
        [FromServices] IEndSessionResponseFormatter formatter,
        [FromQueryOrForm] EndSessionRequest request)
    {
        Core.EndSessionRequest coreEndSessionRequest = request;
        var response = await handler.HandleAsync(coreEndSessionRequest);
        return await formatter.FormatResponseAsync(coreEndSessionRequest, response);
    }

    /// <summary>
    /// Monitors the user's session state by handling requests to the check session endpoint, typically used
    /// within an iframe for session management.
    /// </summary>
    /// <param name="handler">The handler responsible for the check session operation.</param>
    /// <param name="formatter">The formatter used to generate a response suitable for session checking
    /// within an iframe.</param>
    /// <returns>A task that returns an action result for
    /// the check session response.</returns>
    /// <remarks>
    /// This endpoint is part of the OpenID Connect session management specification,
    /// enabling clients to monitor the authentication state.
    /// <see href="https://openid.net/specs/openid-connect-session-1_0.html#OPiframe">
    /// OpenID Connect Check Session Documentation
    /// </see>
    /// </remarks>
    [HttpGet(Path.CheckSession)]
    // The frame is an HTML document loaded in an iframe, and the result writes text/html itself. The
    // attribute never reaches the response, so its only readers are generated OpenAPI documents and content
    // negotiation - which is exactly why it has to agree with what is sent.
    [Produces(MediaTypeNames.Text.Html)]
    [EnableCors(OidcConstants.CorsPolicyName)]
    [EnabledBy(OidcEndpoints.CheckSession)]
    public async Task<ActionResult> CheckSessionAsync(
        [FromServices] ICheckSessionHandler handler,
        [FromServices] ICheckSessionResponseFormatter formatter)
    {
        var response = await handler.HandleAsync();
        return await formatter.FormatResponseAsync(response);
    }
}
