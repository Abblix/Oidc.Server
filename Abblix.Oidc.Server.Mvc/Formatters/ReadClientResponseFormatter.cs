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
using Abblix.Utils;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for reading client responses.
/// </summary>
public class ReadClientResponseFormatter : IReadClientResponseFormatter
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
    public Task<ActionResult> FormatResponseAsync(ClientRequest request, Result<ReadClientSuccessfulResponse, AuthError> response)
    {
        return Task.FromResult(response.Match(
            onSuccess: success => (ActionResult)new OkObjectResult(success),
            onFailure: error => new NotFoundObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));
    }
}
