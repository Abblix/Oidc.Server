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
    /// A task that represents the asynchronous operation. The task result contains the formatted action result.
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
