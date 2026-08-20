// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TokenResponse = Abblix.Oidc.Server.Model.TokenResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formatter for token responses.
/// </summary>
/// <param name="issuerProvider">Supplies the issuer identifier used as the realm value on
/// <c>WWW-Authenticate</c> challenges for client-authentication failures.</param>
public class TokenResponseFormatter(IIssuerProvider issuerProvider) : ITokenResponseFormatter
{
    /// <summary>
    /// Asynchronously formats the response for a token request.
    /// </summary>
    /// <param name="request">The token request.</param>
    /// <param name="response">The response from the token endpoint.</param>
    /// <returns>
    /// A task that returns the formatted token response.
    /// </returns>
    public Task<ActionResult<TokenResponse>> FormatResponseAsync(
        TokenRequest request,
        Result<TokenIssued, OidcError> response)
    {
        return Task.FromResult(response.Match(
            onSuccess: success =>
            {
                var tokenResponse = new TokenResponse
                {
                    AccessToken = success.AccessToken.EncodedJwt,
                    TokenType = success.TokenType,
                    IssuedTokenType = success.IssuedTokenType,
                    ExpiresIn = success.ExpiresIn,

                    RefreshToken = success.RefreshToken?.EncodedJwt,
                    Scope = success.Scope.ToArray(),
                    IdToken = success.IdToken?.EncodedJwt,
                    AuthorizationDetails = success.AuthorizationDetails,
                };

                return new ActionResult<TokenResponse>(new OkObjectResult(tokenResponse));
            },
            onFailure: FormatError));
    }

    private ActionResult<TokenResponse> FormatError(OidcError error)
    {
        // The shared formatter owns the status-code policy: invalid_client comes back as a 401
        // with a Basic challenge (RFC 6749 §5.2), everything else as 400 with the JSON envelope.
        var result = error.Format(StatusCodes.Status400BadRequest, issuerProvider.GetIssuer());

        // Per RFC 9449 §8 a use_dpop_nonce error MUST carry the fresh nonce on a
        // DPoP-Nonce response header alongside the standard error JSON envelope.
        // §8.2 also asks responses bearing DPoP-Nonce to be uncacheable; the controller's
        // [ResponseCache(NoStore)] covers that for every token-endpoint response.
        if (error is UseDPoPNonceError { Nonce: var nonce })
            result = result.WithHeader(HttpRequestHeaders.DPoPNonce, nonce);

        return new ActionResult<TokenResponse>(result);
    }
}
