// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
