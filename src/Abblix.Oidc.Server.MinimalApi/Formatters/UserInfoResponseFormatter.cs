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
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats UserInfo results as <see cref="IResult"/>: the plain claims JSON, or, when the client registered a
/// <c>userinfo_signed_response_alg</c>, a signed (and optionally encrypted) JWT carrying the same claims (OpenID
/// Connect Core 5.3.2). On failure it returns the RFC 6750 / RFC 9449 §7.1 challenge response that advertises both the
/// DPoP and Bearer schemes.
/// </summary>
public class UserInfoResponseFormatter(
    TimeProvider clock,
    IClientJwtFormatter clientJwtFormatter,
    IIssuerProvider issuerProvider,
    IOptionsSnapshot<OidcOptions> options) : IUserInfoResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(
        UserInfoRequest request,
        Result<UserInfoFoundResponse, OidcError> response)
        => response.MatchAsync(
            onSuccess: FormatSuccessAsync,
            onFailure: error => Task.FromResult(
                error.Format(
                    StatusCodes.Status401Unauthorized,
                    issuerProvider.GetIssuer(),
                    DPoPAlgorithms.Allowed,
                    advertiseBearer: true)));

    private async Task<IResult> FormatSuccessAsync(UserInfoFoundResponse found)
    {
        if (found.ClientInfo.UserInfoSignedResponseAlgorithm == SigningAlgorithms.None)
            return Results.Json(found.User);

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
            token,
            found.ClientInfo,
            ClientJwtEncryption.ForUserInfo(found.ClientInfo, options.Value));

        return Results.Content(jwt, MediaTypes.Jwt);
    }
}
