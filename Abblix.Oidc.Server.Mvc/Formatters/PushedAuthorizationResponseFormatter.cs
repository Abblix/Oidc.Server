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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Implements response formatting for pushed authorization requests.
/// </summary>
/// <param name="errorFormatter">The formatter for handling authorization errors.</param>
public class PushedAuthorizationResponseFormatter(IAuthorizationErrorFormatter errorFormatter)
    : IPushedAuthorizationResponseFormatter
{
    /// <summary>
    /// Asynchronously formats the response to a pushed authorization request.
    /// </summary>
    /// <param name="request">The original authorization request.</param>
    /// <param name="response">The response from processing the authorization request.
    /// This could be a <see cref="PushedAuthorizationResponse"/> indicating success,
    /// or an <see cref="AuthorizationError"/> indicating failure.</param>
    /// <returns>A task that resolves to an action result suitable for returning from an MVC action,
    /// representing the formatted response. This could include setting specific HTTP status codes
    /// or returning error information.</returns>
    public async Task<ActionResult> FormatResponseAsync(
        AuthorizationRequest request,
        AuthorizationResponse response)
    {
        switch (response)
        {
            case PushedAuthorizationResponse par:

                var modelResponse = new Model.PushedAuthorizationResponse
                {
                    RequestUri = par.RequestUri,
                    ExpiresIn = par.ExpiresIn,
                };

                return new JsonResult(modelResponse) { StatusCode = StatusCodes.Status201Created };

            case AuthorizationError error:
                return await errorFormatter.FormatResponseAsync(request, error);

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }
    }
}
