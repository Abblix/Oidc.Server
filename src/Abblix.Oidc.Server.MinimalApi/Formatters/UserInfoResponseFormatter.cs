// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Abblix.Oidc.Server.AspNetCore;
using Microsoft.Extensions.Options;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats UserInfo results as <see cref="IResult"/>: the plain claims JSON, or, when the client registered a
/// <c>userinfo_signed_response_alg</c>, a signed (and optionally encrypted) JWT carrying the same claims (OpenID
/// Connect Core 5.3.2). On failure it returns the RFC 6750 / RFC 9449 section 7.1 challenge response that advertises both the
/// DPoP and Bearer schemes.
/// </summary>
public class UserInfoResponseFormatter(
    TimeProvider clock,
    IClientJwtFormatter clientJwtFormatter,
    ITenantAccessor tenantAccessor,
    IOptionsSnapshot<OidcOptions> options) : IUserInfoResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(
        UserInfoRequest request,
        Result<UserInfoFoundResponse, OidcError> response)
        => response.MatchAsync(
            onSuccess: async found => PrivateWhenTokenInQuery(request, await FormatSuccessAsync(found)),
            onFailure: error => Task.FromResult(
                // RFC 6750 section 3.1: invalid_token and insufficient_scope carry their own status, and what is
                // left at a protected resource is invalid_request, which SHOULD be a 400
                FormatError(error)));

    /// <summary>
    /// RFC 6750 section 3.1: invalid_token and insufficient_scope carry their own status, and what is left at a
    /// protected resource is invalid_request, which SHOULD be a 400.
    /// </summary>
    private IResult FormatError(OidcError error)
        => error.Format(
            StatusCodes.Status400BadRequest,
            tenantAccessor.CurrentTenant().Issuer.OriginalString,
            DPoPAlgorithms.Advertised(error, tenantAccessor.CurrentTenant()),
            advertiseBearer: true);

    /// <summary>
    /// RFC 6750 section 2.3: "Server success (2XX status) responses to these requests SHOULD contain a Cache-Control
    /// header with the "private" option", these being requests carrying the token in the URI query. Merged into the
    /// Cache-Control the endpoint sends on every response, whose no-store it keeps.
    /// </summary>
    private static IResult PrivateWhenTokenInQuery(UserInfoRequest request, IResult result)
        => request.AccessTokenInQuery is null
            ? result
            : result.WithResponse(response => response.AddPrivateCacheDirective());

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
        var tenant = tenantAccessor.CurrentTenant();
        var formatted = await clientJwtFormatter.FormatAsync(
            tenant,
            token,
            found.ClientInfo,
            ClientJwtEncryption.ForUserInfo(found.ClientInfo, options.Value));

        // RFC 6750 section 3.1, invalid_token: "The access token provided is expired, revoked, malformed, or invalid
        // for other reasons". The token's client has a key set its profile leaves nothing in to encrypt to, so the token
        // cannot be answered, and a response sent in the clear would be one the profile forbids
        if (formatted.TryGetFailure(out var refusal))
        {
            return FormatError(new OidcError(ErrorCodes.InvalidToken, refusal.ErrorDescription)
            {
                DPoPAlgorithmsAdmitted =
                    DPoPAlgorithms.AdmittedBy(SecurityProfileRequirements.For(tenant, found.ClientInfo)),
            });
        }

        var jwt = formatted.GetSuccess();

        return Results.Content(jwt, MediaTypes.Jwt);
    }
}
