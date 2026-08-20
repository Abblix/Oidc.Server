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
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formatter for responses to client removal requests.
/// </summary>
public class RemoveClientResponseFormatter : IRemoveClientResponseFormatter
{
    /// <summary>
    /// Asynchronously formats the response for a client removal request.
    /// </summary>
    /// <param name="request">The client request.</param>
    /// <param name="response">The response to the client removal request.</param>
    /// <returns>
    /// A task that returns the formatted action result.
    /// </returns>
    public Task<ActionResult> FormatResponseAsync(
        ClientRequest request,
        Result<RemoveClientSuccessfulResponse, OidcError> response)
        => Task.FromResult(response.Match<ActionResult>(
            onSuccess: _ => new NoContentResult(),
            onFailure: error => error.Format(StatusCodes.Status400BadRequest)));
}
