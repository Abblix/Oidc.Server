// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using CoreModel = Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ParResponse = Abblix.Oidc.Server.Model.PushedAuthorizationResponse;
using Core = Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Implements response formatting for pushed authorization requests.
/// </summary>
/// <remarks>
/// PAR is a server-to-server endpoint per RFC 9126; responses are always JSON. Error responses
/// never redirect - that would land programmatic OAuth clients on a user-facing login page.
/// For the same reason this formatter does not delegate to the browser-flow redirect delivery in
/// <see cref="AuthorizationResponseFormatter"/>, which is intended for the authorization endpoint.
/// </remarks>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
public class PushedAuthorizationResponseFormatter(ITenantAccessor tenantAccessor) : IPushedAuthorizationResponseFormatter
{
    /// <summary>
    /// Asynchronously formats the response to a pushed authorization request.
    /// </summary>
    /// <param name="request">The original authorization request.</param>
    /// <param name="response">The response from processing the authorization request.
    /// This could be a <see cref="Core.PushedAuthorizationResponse"/> indicating success,
    /// or an <see cref="AuthorizationError"/> indicating failure.</param>
    /// <returns>A task that resolves to an action result suitable for returning from an MVC action,
    /// representing the formatted response. This could include setting specific HTTP status codes
    /// or returning error information.</returns>
    public Task<ActionResult> FormatResponseAsync(
        CoreModel.AuthorizationRequest request,
        AuthorizationResponse response)
    {
        ActionResult result = response switch
        {
            Core.PushedAuthorizationResponse par => new JsonResult(
                new ParResponse
                {
                    RequestUri = par.RequestUri,
                    ExpiresIn = par.ExpiresIn,
                })
            {
                StatusCode = StatusCodes.Status201Created,
            },

            // RFC 9126 section 2.3: errors take "the same format as is specified for error responses from the token
            // endpoint in Section 5.2 of [RFC6749]", so through the token endpoint's own policy (invalid_client -> 401
            // with a challenge).
            AuthorizationError error => new OidcError(error.Error, error.ErrorDescription).Format(
                StatusCodes.Status400BadRequest,
                tenantAccessor.CurrentTenant().Issuer.OriginalString),

            _ => throw new UnexpectedTypeException(nameof(response), response.GetType()),
        };

        return Task.FromResult(result);
    }
}
