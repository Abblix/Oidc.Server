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

using System.Linq;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for introspection responses, returning either a plain JSON document (RFC 7662) or,
/// when the client registered <c>introspection_signed_response_alg</c> and requests it via
/// <c>Accept: application/token-introspection+jwt</c>, a signed/encrypted JWT (RFC 9701).
/// </summary>
/// <param name="issuerProvider">Supplies the issuer identifier for error responses and the JWT <c>iss</c> claim.</param>
/// <param name="clientJwtFormatter">Signs and optionally encrypts the JWT introspection response.</param>
/// <param name="clock">Supplies the current time for the JWT <c>iat</c> claim.</param>
/// <param name="options">Supplies the default content-encryption algorithm for JWT introspection responses.</param>
/// <param name="httpContextAccessor">Provides the current request so the formatter can honor the <c>Accept</c>
/// header negotiation defined by RFC 9701 §4.</param>
public class IntrospectionResponseFormatter(
    IIssuerProvider issuerProvider,
    IClientJwtFormatter clientJwtFormatter,
    TimeProvider clock,
    IOptionsSnapshot<OidcOptions> options,
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
            onFailure: error => Task.FromResult(
                error.Format(StatusCodes.Status401Unauthorized, issuerProvider.GetIssuer())));
    }

    private async Task<ActionResult> FormatSuccessAsync(IntrospectionSuccess success)
    {
        var introspectionResponse = success.Claims ?? new JsonObject();
        introspectionResponse.SetProperty("active", success.Active ? "true" : "false");

        var clientInfo = success.ClientInfo;

        // RFC 9701 §4: a JWT response is returned only when the client registered a signing algorithm AND requested
        // the JWT media type via Accept; otherwise the plain RFC 7662 JSON document is returned.
        if (clientInfo.IntrospectionSignedResponseAlgorithm == SigningAlgorithms.None || !AcceptsTokenIntrospectionJwt())
        {
            return new JsonResult(introspectionResponse);
        }

        var now = clock.GetUtcNow();
        var token = new JsonWebToken
        {
            Header =
            {
                Type = JwtTypes.TokenIntrospection,
                Algorithm = clientInfo.IntrospectionSignedResponseAlgorithm,
            },
            Payload =
            {
                IssuedAt = now,
                Issuer = issuerProvider.GetIssuer(),
                Audiences = [clientInfo.ClientId],

                // RFC 9701 §5: the introspection response object is carried as the token_introspection claim. The
                // object is cloned because it is otherwise still parented to the introspected token's payload.
                [IanaClaimTypes.TokenIntrospection] = introspectionResponse.DeepClone(),
            },
        };

        return new ContentResult
        {
            ContentType = MediaTypes.TokenIntrospectionJwt,
            Content = await clientJwtFormatter.FormatAsync(
                token,
                clientInfo,
                ClientJwtEncryption.ForIntrospection(clientInfo, options.Value)),
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
