// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Microsoft.AspNetCore.Http;
using CoreModel = Abblix.Oidc.Server.Model;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;
using ParResponse = Abblix.Oidc.Server.Model.PushedAuthorizationResponse;
using CorePushedAuthorizationResponse = Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats pushed authorization request results as <see cref="IResult"/>. PAR is a server-to-server endpoint
/// (RFC 9126): responses are always JSON and errors never redirect.
/// </summary>
public class PushedAuthorizationResponseFormatter : IPushedAuthorizationResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationResponse response)
    {
        IResult result = response switch
        {
            CorePushedAuthorizationResponse par => Results.Json(
                new ParResponse { RequestUri = par.RequestUri, ExpiresIn = par.ExpiresIn },
                statusCode: StatusCodes.Status201Created),

            AuthorizationError error => Results.Json(
                new CoreModel.ErrorResponse(error.Error, error.ErrorDescription),
                statusCode: error.Error switch
                {
                    ErrorCodes.InvalidClient => StatusCodes.Status401Unauthorized,
                    _ => StatusCodes.Status400BadRequest,
                }),

            _ => throw new UnexpectedTypeException(nameof(response), response.GetType()),
        };

        return Task.FromResult(result);
    }
}
