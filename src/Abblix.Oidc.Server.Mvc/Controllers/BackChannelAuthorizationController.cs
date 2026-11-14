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
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc.Model;
using Abblix.Oidc.Server.Mvc.Filters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Controllers;

/// <summary>
/// Handles the authorization requests a client sends to the server directly rather than through the user's browser:
/// pushed authorization requests, client-initiated backchannel authentication (CIBA) and the device authorization
/// grant.
/// </summary>
[ReturnsOidcInvalidRequest]
[ReturnsLibraryRefusalStatus]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[SkipStatusCodePages]
[RequireHttpsUnlessHttpIssuer]
[RequireHost]
[AwaitTenantLoad]
[RequireTenant]
[OidcRouteValue]
[SuppressMessage("SonarLint", "S6967:ModelState.IsValid should be checked in controller actions", Justification = "ReturnsOidcInvalidRequest answers an invalid model state before any action runs")]
public sealed class BackChannelAuthorizationController : ControllerBase
{
    /// <summary>
    /// Handles the pushed authorization endpoint. This endpoint is used for receiving and processing pushed
    /// authorization requests from clients, validating the request, and generating a response that either contains
    /// a URI for the stored authorization request or an error message.
    /// </summary>
    /// <param name="handler">The handler responsible for processing pushed authorization requests.</param>
    /// <param name="formatter">The service for formatting the authorization response.</param>
    /// <param name="tenantAccessor">Names the tenant the request is served at.</param>
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
    [HttpPost]
    [ActionName(nameof(PushAuthorizeAsync))]
    [Consumes(MediaTypes.FormUrlEncoded)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult<Core.AuthorizationResponse>> PushAuthorizeAsync(
        [FromServices] IPushedAuthorizationHandler handler,
        [FromServices] IPushedAuthorizationResponseFormatter formatter,
        [FromServices] ITenantAccessor tenantAccessor,
        [FromForm] AuthorizationRequest authorizationRequest,
        [FromForm] ClientRequest clientRequest)
    {
        Core.AuthorizationRequest coreAuthorizationRequest = authorizationRequest;
        var response = await handler.HandleAsync(tenantAccessor.CurrentTenant(), coreAuthorizationRequest, clientRequest);
        return await formatter.FormatResponseAsync(coreAuthorizationRequest, response);
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
    /// <param name="tenantAccessor">Names the tenant the request is served at.</param>
    /// <param name="authenticationRequest">
    /// The backchannel authentication request containing user-related authentication parameters.</param>
    /// <param name="clientRequest">
    /// The client request providing the client-related information needed for the request.</param>
    /// <returns>
    /// An <see cref="ActionResult"/> representing the HTTP response to the backchannel authentication request.
    /// The response may indicate successful initiation of the process or an error if the request fails validation.
    /// </returns>
    [HttpPost]
    [ActionName(nameof(BackChannelAuthenticationAsync))]
    [Consumes(MediaTypes.FormUrlEncoded)]
    public async Task<ActionResult> BackChannelAuthenticationAsync(
        [FromServices] IBackChannelAuthenticationHandler handler,
        [FromServices] IBackChannelAuthenticationResponseFormatter formatter,
        [FromServices] ITenantAccessor tenantAccessor,
        [FromForm] BackChannelAuthenticationRequest authenticationRequest,
        [FromForm] ClientRequest clientRequest)
    {
        Core.BackChannelAuthenticationRequest coreAuthenticationRequest = authenticationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(tenantAccessor.CurrentTenant(), coreAuthenticationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreAuthenticationRequest, coreClientRequest, response);
    }

    /// <summary>
    /// Handles the device authorization endpoint for getting user authorization on limited-input devices.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8628">
    /// OAuth 2.0 Device Authorization Grant Documentation
    /// </see>
    /// </remarks>
    [HttpPost]
    [ActionName(nameof(DeviceAuthorizationAsync))]
    [Consumes(MediaTypes.FormUrlEncoded)]
    public async Task<ActionResult> DeviceAuthorizationAsync(
        [FromServices] IDeviceAuthorizationHandler handler,
        [FromServices] IDeviceAuthorizationResponseFormatter formatter,
        [FromServices] ITenantAccessor tenantAccessor,
        [FromForm] DeviceAuthorizationRequest deviceAuthorizationRequest,
        [FromForm] ClientRequest clientRequest)
    {
        Core.DeviceAuthorizationRequest coreDeviceAuthorizationRequest = deviceAuthorizationRequest;
        var response = await handler.HandleAsync(tenantAccessor.CurrentTenant(), coreDeviceAuthorizationRequest, clientRequest);
        return await formatter.FormatResponseAsync(coreDeviceAuthorizationRequest, response);
    }
}
