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
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;

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
    /// A task that returns the formatted user information response.
    /// </returns>
    public async Task<ActionResult> FormatResponseAsync(
        UserInfoRequest request,
        Result<UserInfoFoundResponse, AuthError> response)
    {
        return await response.MatchAsync(
            onSuccess: FormatSuccessAsync,
            onFailure: error => Task.FromResult<ActionResult>(
                new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));
    }

    private async Task<ActionResult> FormatSuccessAsync(UserInfoFoundResponse found)
    {
        if (found.ClientInfo.UserInfoSignedResponseAlgorithm == SigningAlgorithms.None)
        {
            return new JsonResult(found.User);
        }

        var token = new JsonWebToken
        {
            Header = { Algorithm = found.ClientInfo.UserInfoSignedResponseAlgorithm },
            Payload = new JsonWebTokenPayload(found.User)
            {
                Issuer = found.Issuer,
                IssuedAt = _clock.GetUtcNow(),
                Audiences = [found.ClientInfo.ClientId],
            }
        };

        return new ContentResult
        {
            ContentType = MediaTypes.Jwt,
            Content = await _clientJwtFormatter.FormatAsync(token, found.ClientInfo),
        };
    }
}
