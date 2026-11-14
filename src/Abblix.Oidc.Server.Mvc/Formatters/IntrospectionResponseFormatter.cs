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
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for introspection responses, returning either a plain JSON document (RFC 7662) or,
/// when the caller requests it via <c>Accept: application/token-introspection+jwt</c>, a signed/encrypted JWT
/// (RFC 9701); a caller that authenticated with nothing is answered with the HTTP 400 RFC 9701 section 5 has.
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
    /// <summary>
    /// Formats an introspection response asynchronously.
    /// </summary>
    /// <param name="request">The introspection request.</param>
    /// <param name="response">The introspection response model.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// </returns>
    public Task<ActionResult> FormatResponseAsync(IntrospectionRequest request, Result<IntrospectionSuccess, OidcError> response)
    {
        return response.MatchAsync(
            onSuccess: FormatSuccessAsync,
            onFailure: error => Task.FromResult(FormatFailure(error)));
    }

    private ActionResult FormatFailure(OidcError error) => error switch
    {
        // RFC 9701 section 5: "return an HTTP status code 400", without the Basic challenge of a failed credential
        UnauthenticatedCallerError => new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription)),

        _ => error.Format(StatusCodes.Status401Unauthorized, tenantAccessor.CurrentTenant().Issuer.OriginalString),
    };

    private async Task<ActionResult> FormatSuccessAsync(IntrospectionSuccess success)
    {
        var introspectionResponse = success.Claims ?? new JsonObject();

        // RFC 7662 section 2.2: active is the only REQUIRED member and its type is a JSON boolean. Serializing it
        // as the strings "true"/"false" (as before) broke strict deserializers and, worse, inverted the
        // semantics for lenient ones: a non-empty string "false" is truthy, so a revoked token could be
        // treated as active by the resource server.
        introspectionResponse.SetProperty(IntrospectionSuccess.Parameters.Active, JsonValue.Create(success.Active));

        // RFC 9701 section 4: the caller requests a JWT response with the Accept header; otherwise the plain RFC 7662
        // JSON document is returned
        if (!AcceptsTokenIntrospectionJwt())
        {
            return new JsonResult(introspectionResponse);
        }

        return new ContentResult
        {
            ContentType = MediaTypes.TokenIntrospectionJwt,
            Content = await jwtBuilder.BuildAsync(tenantAccessor.CurrentTenant(), success.ClientInfo, introspectionResponse),
        };
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
