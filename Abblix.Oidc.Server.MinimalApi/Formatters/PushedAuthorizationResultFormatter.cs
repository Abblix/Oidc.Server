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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Microsoft.AspNetCore.Http;
using CoreModel = Abblix.Oidc.Server.Model;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;
using ParResponse = Abblix.Oidc.Server.Model.PushedAuthorizationResponse;
using CorePushedAuthorizationResponse = Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats pushed authorization request results as <see cref="IResult"/>. PAR is a server-to-server endpoint
/// (RFC 9126): responses are always JSON and errors never redirect.
/// </summary>
public class PushedAuthorizationResultFormatter : IPushedAuthorizationResultFormatter
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
