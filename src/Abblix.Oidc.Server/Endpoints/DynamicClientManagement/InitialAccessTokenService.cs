// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

/// <summary>
/// Issues initial access tokens for authorizing client registration per RFC 7591 Section 3.
/// </summary>
public class InitialAccessTokenService(
    IAuthServiceJwtFormatter serviceJwtFormatter,
    IIssuerProvider issuerProvider,
    IOptions<OidcOptions> options) : IInitialAccessTokenService
{
    /// <inheritdoc />
    public Task<string> IssueTokenAsync(string subject, DateTimeOffset issuedAt, TimeSpan? expiresIn)
    {
        var signing = options.Value.ServiceTokens.InitialAccessToken.Signing;
        var issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer());

        var token = new JsonWebToken
        {
            Header =
            {
                Type = JwtTypes.InitialAccessToken,
                Algorithm = signing.Algorithm,
                KeyId = signing.KeyId,
            },
            Payload =
            {
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + expiresIn,

                Issuer = issuer,

                // RFC 7591 Section 3 has this token authorize a registration call at this server, so this
                // server is what consumes it - and naming itself is what makes the audience checkable on the
                // way back in. Every other token issued here for its own consumption does the same.
                Audiences = [issuer],
                Subject = subject,
            },
        };

        return serviceJwtFormatter.FormatAsync(
            token, ServiceJwtEncryption.ForInitialAccessToken(options.Value));
    }
}
