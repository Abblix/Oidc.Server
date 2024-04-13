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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Mvc;
using UserInfoResponse = Abblix.Oidc.Server.Mvc.Model.UserInfoResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formatter for user information responses.
/// </summary>
public class UserInfoResponseFormatter : IUserInfoResponseFormatter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserInfoResponseFormatter"/> class.
    /// </summary>
    /// <param name="clock">Provides the current time.</param>
    /// <param name="clientJwtFormatter">Formats JWTs for clients.</param>
    public UserInfoResponseFormatter(
        TimeProvider clock,
        IClientJwtFormatter clientJwtFormatter)
    {
        _clock = clock;
        _clientJwtFormatter = clientJwtFormatter;
    }

    private readonly IClientJwtFormatter _clientJwtFormatter;
    private readonly TimeProvider _clock;

    /// <summary>
    /// Asynchronously formats the response for a user information request.
    /// </summary>
    /// <remarks>
    /// This method handles different types of user information responses and formats them
    /// into appropriate HTTP action results.
    /// </remarks>
    /// <param name="request">The user information request.</param>
    /// <param name="response">The response from the user information endpoint.</param>
    /// <returns>
    /// A task that represents the asynchronous operation. The task result contains the formatted user information response.
    /// </returns>
    public async Task<ActionResult<UserInfoResponse>> FormatResponseAsync(
        UserInfoRequest request,
        Endpoints.UserInfo.Interfaces.UserInfoResponse response)
    {
        switch (response)
        {
            case UserInfoFoundResponse
                {
                    ClientInfo: var clientInfo,
                    User: var user,
                    Issuer: var issuer,
                }
                when clientInfo.UserInfoSignedResponseAlgorithm != SigningAlgorithms.None:

                var token = new JsonWebToken
                {
                    Header = { Algorithm = clientInfo.UserInfoSignedResponseAlgorithm },
                    Payload = new JsonWebTokenPayload(user)
                    {
                        Issuer = issuer,
                        IssuedAt = _clock.GetUtcNow(),
                        Audiences = new[] { clientInfo.ClientId },
                    }
                };

                return new ContentResult
                {
                    ContentType = MediaTypes.Jwt,
                    Content = await _clientJwtFormatter.FormatAsync(token, clientInfo),
                };

            case UserInfoFoundResponse { User: var user }:
                return new JsonResult(user);

            case UserInfoErrorResponse error:
                return new BadRequestObjectResult(error);

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }
    }
}
