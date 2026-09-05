// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Controllers;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for reading client responses.
/// </summary>
/// <param name="uriResolver">The URI resolver for generating client management URLs.</param>
public class ReadClientResponseFormatter(IUriResolver uriResolver) : IReadClientResponseFormatter
{
    /// <summary>
    /// Formats a response for reading a client asynchronously.
    /// </summary>
    /// <param name="request">The client request.</param>
    /// <param name="response">The client response model.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// </returns>
    /// <remarks>
    /// This method is used to format the response for reading a client.
    /// Depending on the response type, it creates different types of ActionResult to be returned to the client.
    /// </remarks>
    public Task<ActionResult> FormatResponseAsync(
        ClientRequest request,
        Result<ReadClientSuccessfulResponse, OidcError> response)
    {
        return Task.FromResult(response.Match<ActionResult>(
            success => new OkObjectResult(success with
            {
                RegistrationClientUri = success.RegistrationAccessToken.HasValue()
                    ? uriResolver.Action(
                        MvcUtils.TrimAsync(nameof(ClientManagementController.ReadClientAsync)),
                        MvcUtils.NameOf<ClientManagementController>(),
                        new RouteValueDictionary
                        {
                            { "clientId", success.ClientId },
                        })
                    : null
            }),
            error => error.Format(StatusCodes.Status404NotFound)));
    }
}
