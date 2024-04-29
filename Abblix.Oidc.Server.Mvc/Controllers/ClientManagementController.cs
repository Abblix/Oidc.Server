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
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
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
public class ClientManagementController : ControllerBase
{
    /// <summary>
    /// Registers a new client dynamically with the authorization server. This endpoint processes the client
    /// registration requests by validating the provided details and creating a new client configuration.
    /// </summary>
    /// <param name="handler">The handler responsible for processing client registration requests.</param>
    /// <param name="formatter">The formatter responsible for generating the client registration response.</param>
    /// <param name="request">The details of the client registration request.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an action result that includes
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
    /// <param name="request">The details of the client information request.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an action result that includes
    /// the client information response.</returns>
    /// <remarks>
    /// This method allows clients to query their current configuration stored by the authorization server.
    /// It is compliant with the OpenID Connect Dynamic Client Registration protocol, enabling clients to manage
    /// their registration details post-registration.
    /// </remarks>
    [HttpGet(Path.Register)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> ReadClientAsync(
        [FromServices] IReadClientHandler handler,
        [FromServices] IReadClientResponseFormatter formatter,
        [FromQuery] ClientRequest request)
    {
        var clientRequest = request.Map();
        var response = await handler.HandleAsync(clientRequest);
        return await formatter.FormatResponseAsync(clientRequest, response);
    }

    /// <summary>
    /// Removes a registered client's configuration from the authorization server, effectively revoking its registration
    /// and access.
    /// </summary>
    /// <param name="handler">The handler responsible for processing client removal requests.</param>
    /// <param name="formatter">The formatter responsible for generating the client removal response.</param>
    /// <param name="request">The details of the client removal request.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in an action result that confirms
    /// the client removal.</returns>
    /// <remarks>
    /// This method supports the removal of clients from the authorization server. Following the OpenID Connect Dynamic
    /// Client Registration protocol, it allows for the clean-up of client configurations that are no longer needed
    /// or valid.
    /// </remarks>
    [HttpDelete(Path.Register)]
    [Produces(MediaTypeNames.Application.Json)]
    public async Task<ActionResult> RemoveClientAsync(
        [FromServices] IRemoveClientHandler handler,
        [FromServices] IRemoveClientResponseFormatter formatter,
        [FromQuery] ClientRequest request)
    {
        var clientRequest = request.Map();
        var response = await handler.HandleAsync(clientRequest);
        return await formatter.FormatResponseAsync(clientRequest, response);
    }
}
