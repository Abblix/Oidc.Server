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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats CIBA backchannel authentication results as <see cref="IResult"/>: a JSON success response, a 401 with a
/// <c>WWW-Authenticate</c> challenge matching the client's scheme, a 403, or a 400 with the JSON error envelope.
/// </summary>
/// <param name="issuerProvider">Supplies the issuer used as the realm on client-authentication challenges.</param>
public class BackChannelAuthenticationResultFormatter(IIssuerProvider issuerProvider)
    : IBackChannelAuthenticationResultFormatter
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
                // RFC 9110 §11.6.1: a 401 carries a WWW-Authenticate challenge matching the client's scheme.
                BackChannelAuthenticationUnauthorized { Error: var err, ErrorDescription: var description }
                    => Results.Json(new ErrorResponse(err, description), statusCode: StatusCodes.Status401Unauthorized)
                        .WithHeader(HeaderNames.WWWAuthenticate, FormatClientChallenge(clientRequest)),

                BackChannelAuthenticationForbidden { Error: var err, ErrorDescription: var description }
                    => Results.Json(new ErrorResponse(err, description), statusCode: StatusCodes.Status403Forbidden),

                { Error: var err, ErrorDescription: var description }
                    => Results.Json(new ErrorResponse(err, description), statusCode: StatusCodes.Status400BadRequest),

                _ => throw new UnexpectedTypeException(nameof(error), error.GetType()),
            }));

    /// <summary>
    /// Builds the <c>WWW-Authenticate</c> challenge matching the client's authentication scheme. Per RFC 6749 §5.2 the
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
