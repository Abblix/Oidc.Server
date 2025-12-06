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
                                { ClientRequest.Parameters.ClientId, success.ClientId },
                            })
                        : null
                }),
            error => new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));
    }
}
