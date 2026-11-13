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
using Microsoft.AspNetCore.Http;
using AuthorizationRequest = Abblix.Oidc.Server.Model.AuthorizationRequest;
using ParResponse = Abblix.Oidc.Server.Model.PushedAuthorizationResponse;
using CorePushedAuthorizationResponse = Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces.PushedAuthorizationResponse;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats pushed authorization request results as <see cref="IResult"/>. PAR is a server-to-server endpoint
/// (RFC 9126): responses are always JSON and errors never redirect.
/// </summary>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
public class PushedAuthorizationResponseFormatter(ITenantAccessor tenantAccessor) : IPushedAuthorizationResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(AuthorizationRequest request, AuthorizationResponse response)
    {
        IResult result = response switch
        {
            CorePushedAuthorizationResponse par => Results.Json(
                new ParResponse { RequestUri = par.RequestUri, ExpiresIn = par.ExpiresIn },
                statusCode: StatusCodes.Status201Created),

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
