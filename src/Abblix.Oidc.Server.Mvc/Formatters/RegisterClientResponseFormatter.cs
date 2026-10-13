// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for client registration responses.
/// </summary>
/// <param name="clientUriBuilder">Builds the URL of the client's configuration endpoint.</param>
public class RegisterClientResponseFormatter(RegistrationClientUriBuilder clientUriBuilder) : IRegisterClientResponseFormatter
{
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
            onFailure: error => error.Format(StatusCodes.Status400BadRequest)));
    }

    private ActionResult FormatSuccess(ClientRegistrationRequest request, ClientRegistrationSuccessResponse success)
    {
        var modelResponse = new ClientRegistrationResponse(success.Metadata)
        {
            ClientId = success.ClientId,
            ClientIdIssuedAt = success.ClientIdIssuedAt,

            ClientSecret = success.ClientSecret,
            ClientSecretExpiresAt = success.ClientSecretExpiresAt ?? DateTimeOffset.UnixEpoch,

            RegistrationAccessToken = success.RegistrationAccessToken,

            RegistrationClientUri = success.RegistrationAccessToken.HasValue()
                ? GetClientReadUrl(success.ClientId)
                : null,

            // RFC 7591 section 3.2.1: a software statement "MUST be returned unmodified", and the server keeps none
            SoftwareStatement = request.SoftwareStatement,
        };

        return new ObjectResult(modelResponse) { StatusCode = StatusCodes.Status201Created };
    }

    private Uri GetClientReadUrl(string clientId) => clientUriBuilder.Build(clientId);
}
