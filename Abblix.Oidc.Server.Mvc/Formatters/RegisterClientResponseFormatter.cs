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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for client registration responses.
/// </summary>
public class RegisterClientResponseFormatter : IRegisterClientResponseFormatter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RegisterClientResponseFormatter"/> class.
    /// </summary>
    /// <param name="uriResolver">The action URI provider used for generating URIs for client management actions.</param>
    public RegisterClientResponseFormatter(IUriResolver uriResolver)
    {
        _uriResolver = uriResolver;
    }

    private readonly IUriResolver _uriResolver;

    /// <summary>
    /// Formats a client registration response asynchronously, converting the response model to an appropriate
    /// <see cref="ActionResult"/> based on the nature of the response.
    /// </summary>
    /// <param name="request">The client registration request containing the data submitted by the client.</param>
    /// <param name="response">The client registration response model to be formatted.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// Depending on the response, this may be a success result with client details or an error response.
    /// </returns>
    /// <remarks>
    /// This method handles different types of responses: successful registration and error scenarios.
    /// In the case of successful registration, it returns a 201 Created response with client details.
    /// In the case of an error, it returns a 400 Bad Request response with error details.
    /// </remarks>
    public Task<ActionResult> FormatResponseAsync(
        ClientRegistrationRequest request,
        Result<ClientRegistrationSuccessResponse, OidcError> response)
    {
        return Task.FromResult(response.Match(
            onSuccess: success => FormatSuccess(request, success),
            onFailure: error => (ActionResult)new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));
    }

    private ActionResult FormatSuccess(ClientRegistrationRequest request, ClientRegistrationSuccessResponse success)
    {
        var modelResponse = new Abblix.Oidc.Server.Model.ClientRegistrationResponse
        {
            ClientId = success.ClientId,
            ClientIdIssuedAt = success.ClientIdIssuedAt,

            ClientSecret = success.ClientSecret,
            ClientSecretExpiresAt = success.ClientSecretExpiresAt ?? DateTimeOffset.UnixEpoch,

            RegistrationAccessToken = success.RegistrationAccessToken,

            RegistrationClientUri = success.RegistrationAccessToken.HasValue()
                ? GetClientReadUrl(success.ClientId)
                : null,

            InitiateLoginUri = request.InitiateLoginUri
        };

        return new ObjectResult(modelResponse) { StatusCode = StatusCodes.Status201Created };
    }

    private Uri GetClientReadUrl(string clientId) => _uriResolver.Action(
        MvcUtils.TrimAsync(nameof(ClientManagementController.ReadClientAsync)),
        MvcUtils.NameOf<ClientManagementController>(),
        new RouteValueDictionary
        {
            { ClientRequest.Parameters.ClientId, clientId },
        });
}
