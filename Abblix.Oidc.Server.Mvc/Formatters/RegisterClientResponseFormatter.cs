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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using ClientRegistrationResponse = Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces.ClientRegistrationResponse;

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
        ClientRegistrationResponse response)
    {
        return Task.FromResult(FormatResponse(request, response));
    }

    private ActionResult FormatResponse(ClientRegistrationRequest request, ClientRegistrationResponse response)
    {
        switch (response)
        {
            case ClientRegistrationSuccessResponse success:

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

            case ClientRegistrationErrorResponse error:
                return new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription));

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }
    }

    private Uri GetClientReadUrl(string clientId) => _uriResolver.Action(
        MvcUtils.TrimAsync(nameof(ClientManagementController.ReadClientAsync)),
        MvcUtils.NameOf<ClientManagementController>(),
        new RouteValueDictionary
        {
            { ClientRequest.Parameters.ClientId, clientId },
        });
}
