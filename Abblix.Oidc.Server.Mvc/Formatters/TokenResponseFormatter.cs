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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using TokenResponse = Abblix.Oidc.Server.Mvc.Model.TokenResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formatter for token responses.
/// </summary>
public class TokenResponseFormatter : ITokenResponseFormatter
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
        Result<TokenIssued, AuthError> response)
    {
        return Task.FromResult(response.Match(
            onSuccess: success =>
            {
                //TODO: append headers 'Cache-Control: no-store' and 'Pragma: no-cache' to response - as requires https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
                return new ActionResult<TokenResponse>(new TokenResponse
                {
                    AccessToken = success.AccessToken.EncodedJwt,
                    TokenType = success.TokenType,
                    IssuedTokenType = success.IssuedTokenType,
                    ExpiresIn = success.ExpiresIn,

                    RefreshToken = success.RefreshToken?.EncodedJwt,
                    IdToken = success.IdToken?.EncodedJwt,
                });
            },
            onFailure: error => new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));
    }
}
