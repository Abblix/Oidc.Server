// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Formatter for user information responses.
/// </summary>
public class UserInfoResponseFormatter(
    TimeProvider clock,
    IClientJwtFormatter clientJwtFormatter,
    ITenantAccessor tenantAccessor,
    IOptionsSnapshot<OidcOptions> options) : IUserInfoResponseFormatter
{
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
        Result<UserInfoFoundResponse, OidcError> response)
    {
        return await response.MatchAsync(
            onSuccess: async found => PrivateWhenTokenInQuery(request, await FormatSuccessAsync(found)),
            onFailure: error => Task.FromResult(
                // RFC 6750 section 3.1: invalid_token and insufficient_scope carry their own status, and what is
                // left at a protected resource is invalid_request, which SHOULD be a 400
                error.Format(
                    StatusCodes.Status400BadRequest,
                    tenantAccessor.CurrentTenant().Issuer.OriginalString,
                    DPoPAlgorithms.Allowed,
                    advertiseBearer: true)));
    }

    /// <summary>
    /// RFC 6750 section 2.3: "Server success (2XX status) responses to these requests SHOULD contain a Cache-Control
    /// header with the "private" option", these being requests carrying the token in the URI query. Appended beside
    /// the no-store the endpoint sends on every response, which it does not replace.
    /// </summary>
    private static ActionResult PrivateWhenTokenInQuery(UserInfoRequest request, ActionResult result)
        => request.AccessTokenInQuery is null
            ? result
            : result.WithAppendHeader(HeaderNames.CacheControl, [CacheControlHeaderValue.PrivateString]);

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
                IssuedAt = clock.GetUtcNow(),
                Audiences = [found.ClientInfo.ClientId],
            }
        };

        // A UserInfo response is encrypted with the client's userinfo_encrypted_response_* metadata.
        var jwt = await clientJwtFormatter.FormatAsync(
            tenantAccessor.CurrentTenant(),
            token,
            found.ClientInfo,
            ClientJwtEncryption.ForUserInfo(found.ClientInfo, options.Value));

        return new ContentResult
        {
            ContentType = MediaTypes.Jwt,
            Content = jwt,
        };
    }
}
