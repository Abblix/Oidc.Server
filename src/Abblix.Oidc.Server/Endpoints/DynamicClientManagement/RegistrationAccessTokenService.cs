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
/// Issues registration access tokens for managing registered clients per RFC 7592 Section 3.
/// </summary>
public class RegistrationAccessTokenService(
    IAuthServiceJwtFormatter serviceJwtFormatter,
    IIssuerProvider issuerProvider,
    IOptions<OidcOptions> options) : IRegistrationAccessTokenService
{
    /// <summary>
    /// Issues a registration access token for a registered client.
    /// </summary>
    /// <param name="clientId">The unique identifier of the registered client.</param>
    /// <param name="issuedAt">The timestamp when the token is issued.</param>
    /// <param name="expiresIn">The optional duration after which the token expires.</param>
    /// <param name="tokenId">The identifier (jti) embedded in the token and bound to the client.</param>
    /// <returns>A task that results in the encoded registration access token.</returns>
    public Task<string> IssueTokenAsync(string clientId, DateTimeOffset issuedAt, TimeSpan? expiresIn, string tokenId)
    {
        var signing = options.Value.ServiceTokens.RegistrationAccessToken.Signing;
        var issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer());

        var token = new JsonWebToken
        {
            Header =
            {
                Type = JwtTypes.RegistrationAccessToken,
                Algorithm = signing.Algorithm,
                KeyId = signing.KeyId,
            },
            Payload =
            {
                // The jti binds the token to the client: the validator accepts only the token whose
                // jti matches the value stored on the client, so a rotated token invalidates its
                // predecessors (RFC 7592 section 5).
                JwtId = tokenId,
                IssuedAt = issuedAt,
                NotBefore = issuedAt,
                ExpiresAt = issuedAt + expiresIn,

                Issuer = issuer,

                // The audience names this server, because this server is what reads the token: RFC 7592
                // Section 3 has the client present it back to the client configuration endpoint as a bearer
                // token, and it never opens it. Which registration the token is about is a different question,
                // and the subject below is what answers it.
                Audiences = [issuer],
                Subject = clientId,
            },
        };

        return serviceJwtFormatter.FormatAsync(
            token, ServiceJwtEncryption.ForRegistrationAccessToken(options.Value));
    }
}
