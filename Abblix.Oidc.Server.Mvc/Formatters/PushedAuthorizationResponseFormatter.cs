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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Implements response formatting for pushed authorization requests, extending the base functionality to handle
/// specific response types.
/// </summary>
public class PushedAuthorizationResponseFormatter : AuthorizationErrorFormatter, IPushedAuthorizationResponseFormatter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PushedAuthorizationResponseFormatter"/> class
    /// with the specified parameters provider.
    /// </summary>
    /// <param name="parametersProvider">Provides access to parameters used in formatting the response.</param>
    public PushedAuthorizationResponseFormatter(IParametersProvider parametersProvider)
        : base(parametersProvider)
    {
    }

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
                return await base.FormatResponseAsync(request, error);

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }
    }
}
