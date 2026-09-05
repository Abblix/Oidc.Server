// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of responses for back-channel authentication requests.
/// This class ensures that the appropriate HTTP responses are generated based on the type of back-channel
/// authentication response, encapsulating success or error scenarios as defined by OAuth 2.0 standards.
/// </summary>
public class BackChannelAuthenticationResponseFormatter(
    IIssuerProvider issuerProvider) : IBackChannelAuthenticationResponseFormatter
{
    /// <summary>
    /// This method transforms the back-channel authentication response into a suitable HTTP response,
    /// ensuring that different outcomes (success or various types of errors) are appropriately represented
    /// as HTTP status codes and payloads.
    /// </summary>
    /// <param name="request">The original back-channel authentication request that triggered the response.</param>
    /// <param name="clientRequest">The client request containing authentication details.</param>
    /// <param name="response">The back-channel authentication response result that needs to be formatted into an HTTP result.
    /// </param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation,
    /// with the formatted response as an <see cref="ActionResult"/>.</returns>
    /// <remarks>
    /// This method formats successful authentication requests as <c>200 OK</c>,
    /// client-related errors as <c>401 Unauthorized</c> or <c>403 Forbidden</c>,
    /// and general errors as <c>400 Bad Request</c>.
    /// Per RFC 9110 Section 11.6.1, all <c>401</c> responses include a <c>WWW-Authenticate</c> header
    /// matching the client's authentication scheme per RFC 6749 Section 5.2.
    /// </remarks>
    public Task<ActionResult> FormatResponseAsync(
        BackChannelAuthenticationRequest request,
        ClientRequest clientRequest,
        Result<BackChannelAuthenticationSuccess, OidcError> response)
    {
        return Task.FromResult(response.Match<ActionResult>(
            onSuccess: success => new OkObjectResult(success),
            onFailure: error =>
            {
                return error switch
                {
                    BackChannelAuthenticationUnauthorized { Error: var err, ErrorDescription: var description }
                        => new UnauthorizedObjectResult(new ErrorResponse(err, description))
                            .WithHeader(HeaderNames.WWWAuthenticate, FormatClientChallenge(clientRequest)),

                    BackChannelAuthenticationForbidden { Error: var err, ErrorDescription: var description }
                        => new ObjectResult(new ErrorResponse(err, description))
                            { StatusCode = StatusCodes.Status403Forbidden },

                    { Error: var err, ErrorDescription: var description }
                        => new BadRequestObjectResult(new ErrorResponse(err, description)),

                    _ => throw new UnexpectedTypeException(nameof(error), error.GetType()),
                };
            }));
    }

    /// <summary>
    /// Builds the <c>WWW-Authenticate</c> challenge matching the client's authentication scheme.
    /// Per RFC 6749 Section 5.2, the challenge scheme MUST match what the client attempted.
    /// Falls back to <c>Bearer</c> when the client did not use the <c>Authorization</c> header
    /// (e.g., <c>client_secret_post</c> or <c>private_key_jwt</c>).
    /// </summary>
    private string FormatClientChallenge(ClientRequest clientRequest)
    {
        var scheme = TokenTypes.Basic.Equals(clientRequest.AuthorizationHeader?.Scheme, StringComparison.OrdinalIgnoreCase)
            ? TokenTypes.Basic
            : TokenTypes.Bearer;

        return $"{scheme} realm=\"{issuerProvider.GetIssuer()}\"";
    }
}
