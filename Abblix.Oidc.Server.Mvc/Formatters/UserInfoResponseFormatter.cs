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
