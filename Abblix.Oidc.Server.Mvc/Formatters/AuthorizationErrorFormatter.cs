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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
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
/// <param name="parametersProvider">The provider for extracting and formatting response parameters,
/// which includes details like state and error descriptions.</param>
/// <param name="issuerProvider">The provider for the issuer URL, ensuring the 'iss' claim is correctly
/// included in error responses if applicable.</param>
public class AuthorizationErrorFormatter(
    IParametersProvider parametersProvider,
    IIssuerProvider issuerProvider)
{
    /// <summary>
    /// Asynchronously formats an authorization error response into an HTTP action result,
    /// considering the request's redirect URI and the error details.
    /// </summary>
    /// <param name="request">The original authorization request that led to the error.</param>
    /// <param name="error">The authorization error to be formatted.</param>
    /// <returns>A task that resolves to the formatted HTTP action result.</returns>
    public Task<ActionResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationError error)
        => Task.FromResult(FormatResponse(request, error));

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
            case { RedirectUri: {} redirectUri }:

                var response = new AuthorizationResponse
                {
                    State = request.State,
                    Issuer = issuerProvider.GetIssuer(),
                    Error = error.Error,
                    ErrorDescription = error.ErrorDescription,
                    ErrorUri = error.ErrorUri,
                };

                return ToActionResult(response, error.ResponseMode, redirectUri);

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
                Formatters = { new AutoPostFormatter(parametersProvider, redirectUri) },
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
        => parametersProvider.GetParameters(response).ToArray();
}
