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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Mvc.Model;
using Abblix.Oidc.Server.Mvc.Attributes;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using AuthorizationResponse = Abblix.Oidc.Server.Mvc.Model.AuthorizationResponse;
using UserInfoResponse = Abblix.Oidc.Server.Mvc.Model.UserInfoResponse;

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
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[SkipStatusCodePages]
[RequireHttps]
public sealed class AuthenticationController : ControllerBase
{
    /// <summary>
    /// Handles the pushed authorization endpoint. This endpoint is used for receiving and processing pushed
    /// authorization requests from clients, validating the request, and generating a response that either contains
    /// a URI for the stored authorization request or an error message.
    /// </summary>
    /// <param name="handler">The handler responsible for processing pushed authorization requests.</param>
    /// <param name="formatter">The service for formatting the authorization response.</param>
    /// <param name="authorizationRequest">The authorization request received from the client.</param>
    /// <param name="clientRequest">Additional client request information for contextual validation.</param>
    /// <returns>
    /// An action result containing the formatted authorization response, which can be a success or an error response.
    /// </returns>
    /// <remarks>
    /// This method first validates the incoming authorization request.
    /// If the request is valid, it is processed and stored, and a response containing the request URI is returned.
    /// If the request is invalid, an error response is generated.
    /// </remarks>
    [HttpPost(Path.PushAuthorizationRequest)]
    [Consumes(MediaTypes.FormUrlEncoded)]
    [Produces(MediaTypeNames.Text.Html, MediaTypeNames.Application.Json)]
    public async Task<ActionResult<AuthorizationResponse>> PushAuthorizeAsync(
        [FromServices] IPushedAuthorizationHandler handler,
        [FromServices] IPushedAuthorizationResponseFormatter formatter,
        [FromForm] AuthorizationRequest authorizationRequest,
        [FromForm] ClientRequest clientRequest)
    {
        var mappedAuthorizationRequest = authorizationRequest.Map();
        var mappedClientRequest = clientRequest.Map();
        var response = await handler.HandleAsync(mappedAuthorizationRequest, mappedClientRequest);
        return await formatter.FormatResponseAsync(mappedAuthorizationRequest, response);
    }

    /// <summary>
    /// Handles requests to the authorization endpoint, performing user authentication and getting consent for
    /// requested scopes.
    /// </summary>
    /// <param name="handler">The handler responsible for processing authorization requests.</param>
    /// <param name="formatter">The formatter used to generate a response for the authorization request.</param>
    /// <param name="request">The authorization request details received from the client.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an action result containing
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
    public async Task<ActionResult<AuthorizationResponse>> AuthorizeAsync(
        [FromServices] IAuthorizationHandler handler,
        [FromServices] IAuthorizationResponseFormatter formatter,
        [FromQueryOrForm] AuthorizationRequest request)
    {
        var authorizationRequest = request.Map();
        var response = await handler.HandleAsync(authorizationRequest);
        return await formatter.FormatResponseAsync(authorizationRequest, response);
    }

    /// <summary>
    /// Processes requests to the userinfo endpoint, returning claims about the authenticated user based on
    /// the provided access token.
    /// </summary>
    /// <param name="handler">The handler responsible for processing userinfo requests.</param>
    /// <param name="formatter">The formatter used to generate a response with user claims.</param>
    /// <param name="userInfoRequest">The userinfo request containing the access token.</param>
    /// <param name="clientRequest">Additional request information provided by the client.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an action result containing
    /// the userinfo response.</returns>
    /// <remarks>
    /// This endpoint provides claims about the authenticated user, conforming to the
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">
    /// OpenID Connect UserInfo Endpoint Documentation
    /// </see>
    /// </remarks>
    [HttpGetOrPost(Path.UserInfo)]
    [EnableCors(OidcConstants.CorsPolicyName)]
    public async Task<ActionResult<UserInfoResponse>> UserInfoAsync(
        [FromServices] IUserInfoHandler handler,
        [FromServices] IUserInfoResponseFormatter formatter,
        [FromQueryOrForm] UserInfoRequest userInfoRequest,
        [FromQueryOrForm] ClientRequest clientRequest)
    {
        var mappedUserInfoRequest = userInfoRequest.Map();
        var mappedClientRequest = clientRequest.Map();
        var response = await handler.HandleAsync(mappedUserInfoRequest, mappedClientRequest);
        return await formatter.FormatResponseAsync(mappedUserInfoRequest, response);
    }

    /// <summary>
    /// Facilitates the logout process by handling requests to the end session endpoint,
    /// allowing clients to terminate the user's session.
    /// </summary>
    /// <param name="handler">The handler responsible for processing end session requests.</param>
    /// <param name="formatter">The formatter used to generate a response for the end session request.</param>
    /// <param name="request">The end session request details received from the client.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an action result for
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
    public async Task<ActionResult> EndSessionAsync(
        [FromServices] IEndSessionHandler handler,
        [FromServices] IEndSessionResponseFormatter formatter,
        [FromQueryOrForm] EndSessionRequest request)
    {
        var endSessionRequest = request.Map();
        var response = await handler.HandleAsync(endSessionRequest);
        return await formatter.FormatResponseAsync(endSessionRequest, response);
    }

    /// <summary>
    /// Monitors the user's session state by handling requests to the check session endpoint, typically used
    /// within an iframe for session management.
    /// </summary>
    /// <param name="handler">The handler responsible for the check session operation.</param>
    /// <param name="formatter">The formatter used to generate a response suitable for session checking
    /// within an iframe.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an action result for
    /// the check session response.</returns>
    /// <remarks>
    /// This endpoint is part of the OpenID Connect session management specification,
    /// enabling clients to monitor the authentication state.
    /// <see href="https://openid.net/specs/openid-connect-session-1_0.html#OPiframe">
    /// OpenID Connect Check Session Documentation
    /// </see>
    /// </remarks>
    [HttpGet(Path.CheckSession)]
    [Produces(MediaTypes.Javascript)]
    [EnableCors(OidcConstants.CorsPolicyName)]
    public async Task<ActionResult> CheckSessionAsync(
        [FromServices] ICheckSessionHandler handler,
        [FromServices] ICheckSessionResponseFormatter formatter)
    {
        var response = await handler.HandleAsync();
        return await formatter.FormatResponseAsync(response);
    }

    /// <summary>
    /// Handles the backchannel authentication endpoint, initiating the authentication flow that occurs outside
    /// the traditional user-agent interaction as specified by CIBA.
    /// </summary>
    /// <remarks>
    /// The method implements the CIBA (Client-Initiated Backchannel Authentication) protocol,
    /// enabling the authentication of a user through an out-of-band mechanism.
    /// Clients initiate the authentication request, and the user's authentication happens through a separate channel
    /// (e.g., mobile device).
    ///
    /// For more details, refer to the CIBA documentation:
    /// <see href="https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.7">
    /// CIBA - Client Initiated Backchannel Authentication Documentation
    /// </see>
    /// </remarks>
    /// <param name="handler">
    /// Service that processes the authentication request, validating and initiating the backchannel flow.</param>
    /// <param name="formatter">
    /// Service that formats the response to the client, based on the result of the backchannel authentication request.
    /// </param>
    /// <param name="authenticationRequest">
    /// The backchannel authentication request containing user-related authentication parameters.</param>
    /// <param name="clientRequest">
    /// The client request providing the client-related information needed for the request.</param>
    /// <returns>
    /// An <see cref="ActionResult"/> representing the HTTP response to the backchannel authentication request.
    /// The response may indicate successful initiation of the process or an error if the request fails validation.
    /// </returns>
    [HttpPost(Path.BackchannelAuthentication)]
    [Consumes(MediaTypes.FormUrlEncoded)]
    public async Task<ActionResult> BackChannelAuthenticationAsync(
        [FromServices] IBackChannelAuthenticationHandler handler,
        [FromServices] IBackChannelAuthenticationResponseFormatter formatter,
        [FromForm] BackChannelAuthenticationRequest authenticationRequest,
        [FromForm] ClientRequest clientRequest)
    {
        var mappedAuthenticationRequest = authenticationRequest.Map();
        var mappedClientRequest = clientRequest.Map();
        var response = await handler.HandleAsync(mappedAuthenticationRequest, mappedClientRequest);
        return await formatter.FormatResponseAsync(mappedAuthenticationRequest, response);
    }

    /*
    /// <summary>
    /// Handles the device authorization endpoint for getting user authorization on limited-input devices.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628">
    /// OAuth 2.0 Device Authorization Grant Documentation
    /// </see>
    /// </remarks>
    [HttpPost(Path.DeviceAuthorization)]
    [Consumes(MediaTypes.FormUrlEncoded)]
    public Task<ActionResult> DeviceAuthorizationAsync()
    {
        throw new NotImplementedException();
    }*/
}
