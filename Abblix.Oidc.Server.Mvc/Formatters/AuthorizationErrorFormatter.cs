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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using AuthorizationResponse = Abblix.Oidc.Server.Mvc.Model.AuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of authorization error responses, converting them into an appropriate HTTP action
/// result based on the specified response mode and the nature of the error.
/// </summary>
public class AuthorizationErrorFormatter
{
    /// <summary>
    /// Initializes a new instance of <see cref="AuthorizationErrorFormatter"/> with the necessary parameter provider.
    /// </summary>
    /// <param name="parametersProvider">The provider for extracting and formatting response parameters.</param>
    public AuthorizationErrorFormatter(IParametersProvider parametersProvider)
    {
        _parametersProvider = parametersProvider;
    }

    private readonly IParametersProvider _parametersProvider;

    /// <summary>
    /// Asynchronously formats an authorization error response into an HTTP action result,
    /// considering the request's redirect URI and the error details.
    /// </summary>
    /// <param name="request">The original authorization request that led to the error.</param>
    /// <param name="error">The authorization error to be formatted.</param>
    /// <returns>A task that resolves to the formatted HTTP action result.</returns>
    public Task<ActionResult> FormatResponseAsync(
        AuthorizationRequest request,
        AuthorizationError error)
    {
        return Task.FromResult(FormatResponse(request, error));
    }

    /// <summary>
    /// Internally formats the authorization error response based on the request context and the error's properties,
    /// such as whether to use a redirect URI.
    /// </summary>
    /// <param name="request">The authorization request associated with the error.</param>
    /// <param name="error">The error to be formatted into a response.</param>
    /// <returns>The action result representing the formatted error response.</returns>
    private ActionResult FormatResponse(AuthorizationRequest request, AuthorizationError error)
    {
        switch (error)
        {
            case { RedirectUri: not null }:

                var response = new AuthorizationResponse
                {
                    Error = error.Error,
                    ErrorDescription = error.ErrorDescription,
                    ErrorUri = error.ErrorUri,

                    State = request.State,
                };

                return ToActionResult(response, error.ResponseMode, error.RedirectUri);

            default:
                return new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription));
        }
    }

    /// <summary>
    /// Converts an authorization response into the appropriate action result type based on the specified response mode.
    /// </summary>
    /// <param name="response">The authorization response to convert.</param>
    /// <param name="responseMode">The response mode indicating how the response should be delivered.</param>
    /// <param name="redirectUri">The URI to redirect to, if applicable.</param>
    /// <returns>The action result for the given authorization response.</returns>
    protected ActionResult ToActionResult(AuthorizationResponse response, string responseMode, Uri redirectUri)
    {
        return responseMode switch
        {
            ResponseModes.FormPost => new OkObjectResult(response)
            {
                Formatters = { new AutoPostFormatter(_parametersProvider, redirectUri) },
            },

            ResponseModes.Query => new RedirectResult(redirectUri.AddToQuery(GetParametersFrom(response))),
            ResponseModes.Fragment => new RedirectResult(redirectUri.AddToFragment(GetParametersFrom(response))),

            _ => throw new ArgumentOutOfRangeException(nameof(responseMode)),
        };
    }

    /// <summary>
    /// Extracts and formats response parameters from an authorization response.
    /// </summary>
    /// <param name="response">The authorization response containing the parameters.</param>
    /// <returns>An array of name-value pairs representing the response parameters.</returns>
    private (string name, string? value)[] GetParametersFrom(AuthorizationResponse response)
        => _parametersProvider.GetParameters(response).ToArray();
}
