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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using IntrospectionRequest = Abblix.Oidc.Server.Model.IntrospectionRequest;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats introspection results as <see cref="IResult"/>: a plain RFC 7662 JSON document, or, when the client
/// registered <c>introspection_signed_response_alg</c> and requests it via
/// <c>Accept: application/token-introspection+jwt</c>, a signed/encrypted JWT (RFC 9701); the OAuth error otherwise.
/// </summary>
public class IntrospectionResponseFormatter(
    IIssuerProvider issuerProvider,
    IClientJwtFormatter clientJwtFormatter,
    TimeProvider clock,
    IOptionsSnapshot<OidcOptions> options,
    IHttpContextAccessor httpContextAccessor) : IIntrospectionResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(IntrospectionRequest request, Result<IntrospectionSuccess, OidcError> response)
        => response.MatchAsync(
            onSuccess: FormatSuccessAsync,
            onFailure: error => Task.FromResult(
                error.Format(StatusCodes.Status401Unauthorized, issuerProvider.GetIssuer())));

    private async Task<IResult> FormatSuccessAsync(IntrospectionSuccess success)
    {
        var introspectionResponse = success.Claims ?? new JsonObject();

        // RFC 7662 §2.2: active is the only REQUIRED member and is a JSON boolean.
        introspectionResponse.SetProperty(IntrospectionSuccess.Parameters.Active, JsonValue.Create(success.Active));

        var clientInfo = success.ClientInfo;

        // RFC 9701 §4: a JWT response is returned only when the client registered a signing algorithm AND requested
        // the JWT media type via Accept; otherwise the plain RFC 7662 JSON document is returned.
        if (clientInfo.IntrospectionSignedResponseAlgorithm == SigningAlgorithms.None || !AcceptsTokenIntrospectionJwt())
            return Results.Json(introspectionResponse);

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

        var jwt = await clientJwtFormatter.FormatAsync(
            token,
            clientInfo,
            ClientJwtEncryption.ForIntrospection(clientInfo, options.Value));

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
