// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
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
/// Provides a response formatter for update client responses per RFC 7592 Section 2.2.
/// </summary>
/// <param name="uriResolver">The URI resolver for generating client management URLs.</param>
public class UpdateClientResponseFormatter(IUriResolver uriResolver) : IUpdateClientResponseFormatter
{
    /// <summary>
    /// Formats a response for updating a client asynchronously.
    /// </summary>
    /// <param name="request">The client update request.</param>
    /// <param name="response">The client response model.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// Per RFC 7592, returns 200 OK with updated client configuration on success.
    /// </returns>
    public Task<ActionResult> FormatResponseAsync(UpdateClientRequest request, Result<ReadClientSuccessfulResponse, OidcError> response)
    {
        return Task.FromResult(response.Match<ActionResult>(
            success => new OkObjectResult(
                success with
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
            error => error.Format(StatusCodes.Status400BadRequest)));
    }
}
