// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats CIBA backchannel authentication results as <see cref="IResult"/>: a JSON success response, a 401 with a
/// <c>WWW-Authenticate</c> challenge matching the client's scheme, a 403, or a 400 with the JSON error envelope.
/// </summary>
/// <param name="issuerProvider">Supplies the issuer used as the realm on client-authentication challenges.</param>
public class BackChannelAuthenticationResponseFormatter(IIssuerProvider issuerProvider)
    : IBackChannelAuthenticationResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest,
        Result<BackChannelAuthenticationSuccess, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: IResult (success) => Results.Json(success),
            onFailure: error => error switch
            {
                // RFC 9110 section 11.6.1: a 401 carries a WWW-Authenticate challenge matching the client's scheme.
                BackChannelAuthenticationUnauthorized { Error: var err, ErrorDescription: var description }
                    => Results.Json(new ErrorResponse(err, description), statusCode: StatusCodes.Status401Unauthorized)
                        .WithHeader(HeaderNames.WWWAuthenticate, FormatClientChallenge(clientRequest)),

                BackChannelAuthenticationForbidden { Error: var err, ErrorDescription: var description }
                    => Results.Json(new ErrorResponse(err, description), statusCode: StatusCodes.Status403Forbidden),

                // The base-type property pattern matches every non-null OidcError, so it is the exhaustive
                // catch-all for the failure branch - a discard arm here would be reachable only for a null
                // error, which the Result failure value never is, and dereferencing it was the defect.
                { Error: var err, ErrorDescription: var description }
                    => Results.Json(new ErrorResponse(err, description), statusCode: StatusCodes.Status400BadRequest),
            }));

    /// <summary>
    /// Builds the <c>WWW-Authenticate</c> challenge matching the client's authentication scheme. Per RFC 6749 section 5.2 the
    /// challenge scheme must match what the client attempted, falling back to <c>Bearer</c> when the client did not use
    /// the <c>Authorization</c> header (e.g. <c>client_secret_post</c> or <c>private_key_jwt</c>).
    /// </summary>
    private string FormatClientChallenge(ClientRequest clientRequest)
    {
        var scheme = TokenTypes.Basic.Equals(clientRequest.AuthorizationHeader?.Scheme, StringComparison.OrdinalIgnoreCase)
            ? TokenTypes.Basic
            : TokenTypes.Bearer;

        return $"{scheme} realm=\"{issuerProvider.GetIssuer()}\"";
    }
}
