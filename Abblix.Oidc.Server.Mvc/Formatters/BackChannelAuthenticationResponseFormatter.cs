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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of responses for back-channel authentication requests.
/// This class ensures that the appropriate HTTP responses are generated based on the type of back-channel
/// authentication response, encapsulating success or error scenarios as defined by OAuth 2.0 standards.
/// </summary>
public class BackChannelAuthenticationResponseFormatter : IBackChannelAuthenticationResponseFormatter
{
    /// <summary>
    /// This method transforms the back-channel authentication response into a suitable HTTP response,
    /// ensuring that different outcomes (success or various types of errors) are appropriately represented
    /// as HTTP status codes and payloads.
    /// </summary>
    /// <param name="request">The original back-channel authentication request that triggered the response.</param>
    /// <param name="response">The back-channel authentication response that needs to be formatted into an HTTP result.
    /// </param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation,
    /// with the formatted response as an <see cref="ActionResult"/>.</returns>
    /// <remarks>
    /// This method formats successful authentication requests as `200 OK`, client-related errors as `401 Unauthorized`
    /// or `403 Forbidden`, and general errors as `400 Bad Request`.
    /// It provides consistent handling for different response types,
    /// ensuring the API behaves predictably according to the OAuth 2.0 back-channel authentication specification.
    /// </remarks>
    public Task<ActionResult> FormatResponseAsync(
        BackChannelAuthenticationRequest request,
        BackChannelAuthenticationResponse response)
    {
        return Task.FromResult<ActionResult>(response switch
        {
            // If the authentication was successful, return a 200 OK response with the success details.
            BackChannelAuthenticationSuccess success => new OkObjectResult(success),

            // If the error indicates an invalid client, return a 401 Unauthorized response.
            BackChannelAuthenticationError { Error: ErrorCodes.InvalidClient, ErrorDescription: var description }
                => new UnauthorizedObjectResult(new ErrorResponse(ErrorCodes.InvalidClient, description)),

            // If access was denied, return a 403 Forbidden response.
            BackChannelAuthenticationError { Error: ErrorCodes.AccessDenied, ErrorDescription: var description }
                => new ObjectResult(new ErrorResponse(ErrorCodes.InvalidClient, description))
                        { StatusCode = StatusCodes.Status403Forbidden },

            // For any other type of error, return a 400 Bad Request response.
            BackChannelAuthenticationError { Error: var error, ErrorDescription: var description }
                => new BadRequestObjectResult(new ErrorResponse(error, description)),

            // If the response type is unexpected, throw an exception for further debugging.
            _ => throw new UnexpectedTypeException(nameof(response), response.GetType()),
        });
    }
}
