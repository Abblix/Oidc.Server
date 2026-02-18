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
using System.Net.Mime;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Mvc.Filters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Oidc.Server.Mvc.Model;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Controllers;

/// <summary>
/// The ClientManagementController is responsible for handling client-related operations in the context of OAuth 2.0 and
/// OpenID Connect. This includes dynamic client registration, reading client configurations, and deleting registered clients.
/// </summary>
/// <remarks>
/// The controller adheres to the OpenID Connect Dynamic Client Registration protocol, allowing clients to register themselves
/// dynamically with the authorization server. It supports operations like registering new clients, querying existing client configurations,
/// and removing clients. This is crucial for systems where client applications need to be managed programmatically without manual intervention.
/// For detailed protocol specifications, refer to <see href="https://openid.net/specs/openid-connect-registration-1_0.html"/>.
/// </remarks>
[ApiController]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
[SkipStatusCodePages]
[RequireHttps]
[EnabledBy(OidcEndpoints.RegisterClient)]
[SuppressMessage("SonarLint", "S6934:Route attributes should be specified on the controller", Justification = "All action methods have explicit route templates; class-level route is redundant")]
public class ClientManagementController : ControllerBase
{
    /// <summary>
    /// Registers a new client dynamically with the authorization server. This endpoint processes the client
    /// registration requests by validating the provided details and creating a new client configuration.
    /// </summary>
    /// <param name="handler">The handler responsible for processing client registration requests.</param>
    /// <param name="formatter">The formatter responsible for generating the client registration response.</param>
    /// <param name="request">The details of the client registration request.</param>
    /// <returns>A task that returns an action result that includes
    /// the client registration response.</returns>
    /// <remarks>
    /// This method implements the OpenID Connect Dynamic Client Registration protocol, facilitating clients
    /// to register dynamically. It validates the request, processes it if valid, and formats a response that
    /// can include either the successful registration details or an error message.
    /// </remarks>
    [HttpPost(Path.Register)]
    [Produces(MediaTypeNames.Application.Json)]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> RegisterClientAsync(
        [FromServices] IRegisterClientHandler handler,
        [FromServices] IRegisterClientResponseFormatter formatter,
        [FromBody] ClientRegistrationRequest request)
    {
        var clientRegistrationRequest = request.Map();
        var response = await handler.HandleAsync(clientRegistrationRequest);
        return await formatter.FormatResponseAsync(clientRegistrationRequest, response);
    }

    /// <summary>
    /// Retrieves the configuration of a previously registered client from the authorization server.
    /// </summary>
    /// <param name="handler">The handler responsible for processing client information requests.</param>
    /// <param name="formatter">The formatter responsible for generating the client information response.</param>
    /// <param name="authorizationRequest">The client authorization request containing client_id and registration_access_token.</param>
    /// <returns>A task that returns an action result that includes
    /// the client information response.</returns>
    /// <remarks>
    /// This method allows clients to query their current configuration stored by the authorization server.
    /// Per RFC 7592 Section 2.1, the endpoint URL format is /connect/register/{client_id}.
    /// The registration_access_token is passed via Authorization: Bearer header.
    /// </remarks>
    [HttpGet(Path.RegisterClient)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> ReadClientAsync(
        [FromServices] IReadClientHandler handler,
        [FromServices] IReadClientResponseFormatter formatter,
        ClientAuthorizationRequest authorizationRequest)
    {
        var clientRequest = authorizationRequest.ToClientRequest();
        var response = await handler.HandleAsync(clientRequest);
        return await formatter.FormatResponseAsync(clientRequest, response);
    }

    /// <summary>
    /// Updates a registered client's configuration with new metadata per RFC 7592 Section 2.2.
    /// </summary>
    /// <param name="handler">The handler responsible for processing client update requests.</param>
    /// <param name="formatter">The formatter responsible for generating the client update response.</param>
    /// <param name="authorizationRequest">The client authorization request containing client_id and registration_access_token.</param>
    /// <param name="registrationRequest">The updated client metadata from request body.</param>
    /// <returns>A task that returns an action result with the updated client configuration.</returns>
    /// <remarks>
    /// This method implements RFC 7592 OAuth 2.0 Dynamic Client Registration Management Protocol Section 2.2.
    /// Per RFC 7592, the endpoint URL format is /connect/register/{client_id}.
    /// The registration_access_token is passed via Authorization: Bearer header.
    /// The request body must contain all client metadata including the client_id and client_secret.
    /// Returns 200 OK with updated configuration on success.
    /// </remarks>
    [HttpPut(Path.RegisterClient)]
    [Produces(MediaTypeNames.Application.Json)]
    [Consumes(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> UpdateClientAsync(
        [FromServices] IUpdateClientHandler handler,
        [FromServices] IUpdateClientResponseFormatter formatter,
        ClientAuthorizationRequest authorizationRequest,
        [FromBody] ClientRegistrationRequest registrationRequest)
    {
        var updateRequest = new UpdateClientRequest(
            authorizationRequest.ToClientRequest(),
            registrationRequest.Map());
        var response = await handler.HandleAsync(updateRequest);
        return await formatter.FormatResponseAsync(updateRequest, response);
    }

    /// <summary>
    /// Removes a registered client's configuration from the authorization server, effectively revoking its registration
    /// and access.
    /// </summary>
    /// <param name="handler">The handler responsible for processing client removal requests.</param>
    /// <param name="formatter">The formatter responsible for generating the client removal response.</param>
    /// <param name="authorizationRequest">The client authorization request containing client_id and registration_access_token.</param>
    /// <returns>A task that returns an action result that confirms
    /// the client removal.</returns>
    /// <remarks>
    /// This method supports the removal of clients from the authorization server per RFC 7592 Section 2.3.
    /// Per RFC 7592, the endpoint URL format is /connect/register/{client_id}.
    /// The registration_access_token is passed via Authorization: Bearer header.
    /// </remarks>
    [HttpDelete(Path.RegisterClient)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> RemoveClientAsync(
        [FromServices] IRemoveClientHandler handler,
        [FromServices] IRemoveClientResponseFormatter formatter,
        ClientAuthorizationRequest authorizationRequest)
    {
        var clientRequest = authorizationRequest.ToClientRequest();
        var response = await handler.HandleAsync(clientRequest);
        return await formatter.FormatResponseAsync(clientRequest, response);
    }
}
