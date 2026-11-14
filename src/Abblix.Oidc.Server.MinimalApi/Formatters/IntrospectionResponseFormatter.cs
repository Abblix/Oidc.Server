// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.ResponseObject;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using IntrospectionRequest = Abblix.Oidc.Server.Model.IntrospectionRequest;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats introspection results as <see cref="IResult"/>: a plain RFC 7662 JSON document, or, when the client
/// registered <c>introspection_signed_response_alg</c> and requests it via
/// <c>Accept: application/token-introspection+jwt</c>, a signed/encrypted JWT (RFC 9701); the OAuth error otherwise.
/// </summary>
/// <param name="tenantAccessor">Names the tenant the request is served at.</param>
/// <param name="jwtBuilder">Builds the RFC 9701 JWT.</param>
/// <param name="httpContextAccessor">Provides the current request so the formatter can honor the <c>Accept</c>
/// header negotiation defined by RFC 9701 section 4.</param>
public class IntrospectionResponseFormatter(
    ITenantAccessor tenantAccessor,
    IIntrospectionResponseJwtBuilder jwtBuilder,
    IHttpContextAccessor httpContextAccessor) : IIntrospectionResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(IntrospectionRequest request, Result<IntrospectionSuccess, OidcError> response)
        => response.MatchAsync(
            onSuccess: FormatSuccessAsync,
            onFailure: error => Task.FromResult(
                error.Format(StatusCodes.Status401Unauthorized, tenantAccessor.CurrentTenant().Issuer.OriginalString)));

    private async Task<IResult> FormatSuccessAsync(IntrospectionSuccess success)
    {
        var introspectionResponse = success.Claims ?? new JsonObject();

        // RFC 7662 section 2.2: active is the only REQUIRED member and is a JSON boolean.
        introspectionResponse.SetProperty(IntrospectionSuccess.Parameters.Active, JsonValue.Create(success.Active));

        // RFC 9701 section 4: a JWT response is returned only when the client registered a signing algorithm AND requested
        // the JWT media type via Accept; otherwise the plain RFC 7662 JSON document is returned.
        if (success.ClientInfo.IntrospectionSignedResponseAlgorithm == SigningAlgorithms.None || !AcceptsTokenIntrospectionJwt())
            return Results.Json(introspectionResponse);

        var jwt = await jwtBuilder.BuildAsync(tenantAccessor.CurrentTenant(), success.ClientInfo, introspectionResponse);
        return Results.Content(jwt, MediaTypes.TokenIntrospectionJwt);
    }

    private bool AcceptsTokenIntrospectionJwt()
    {
        var request = httpContextAccessor.HttpContext?.Request;
        if (request == null)
            return false;

        return request.GetTypedHeaders().Accept.Any(
            mediaType => mediaType.MediaType.HasValue &&
                         string.Equals(
                             mediaType.MediaType.Value,
                             MediaTypes.TokenIntrospectionJwt,
                             StringComparison.OrdinalIgnoreCase));
    }
}
