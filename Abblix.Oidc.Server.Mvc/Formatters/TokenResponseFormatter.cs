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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
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
    /// A task that represents the asynchronous operation. The task result contains the formatted token response.
    /// </returns>
    public Task<ActionResult<TokenResponse>> FormatResponseAsync(
        TokenRequest request,
        Endpoints.Token.Interfaces.TokenResponse response)
    {
        return Task.FromResult(FormatResponse(response));
    }

    /// <summary>
    /// Formats the response from the token endpoint.
    /// </summary>
    /// <param name="response">The response from the token endpoint.</param>
    /// <returns>
    /// The formatted token response as an <see cref="ActionResult{TValue}"/>.
    /// </returns>
    private static ActionResult<TokenResponse> FormatResponse(Endpoints.Token.Interfaces.TokenResponse response)
    {
        switch (response)
        {
            case TokenIssuedResponse success:
                //TODO: append headers 'Cache-Control: no-store' and 'Pragma: no-cache' to response - as requires https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
                return new TokenResponse
                {
                    AccessToken = success.AccessToken.EncodedJwt,
                    TokenType = success.TokenType,
                    IssuedTokenType = success.IssuedTokenType,
                    ExpiresIn = success.ExpiresIn,

                    RefreshToken = success.RefreshToken?.EncodedJwt,
                    IdToken = success.IdToken?.EncodedJwt,
                };

            case TokenErrorResponse error:
                return new BadRequestObjectResult(error);

            default:
                throw new ArgumentOutOfRangeException(nameof(response));
        }
    }
}
