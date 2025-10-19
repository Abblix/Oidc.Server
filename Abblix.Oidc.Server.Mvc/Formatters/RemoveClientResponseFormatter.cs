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

using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
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
    public Task<ActionResult> FormatResponseAsync(ClientRequest request, RemoveClientResponse response)
        => Task.FromResult(FormatResponse(response));

    /// <summary>
    /// Formats the response for a client removal request.
    /// </summary>
    /// <param name="response">The response to the client removal request.</param>
    /// <returns>The formatted action result.</returns>
    /// <exception cref="UnexpectedTypeException">Thrown when the response type is unexpected.</exception>
    private static ActionResult FormatResponse(RemoveClientResponse response)
    {
        return response switch
        {
            RemoveClientSuccessfulResponse => new NoContentResult(),

            RemoveClientErrorResponse { Error: var error, ErrorDescription: var description }
                => new BadRequestObjectResult(new ErrorResponse(error, description)),

            _ => throw new UnexpectedTypeException(nameof(response), response.GetType())
        };
    }
}
