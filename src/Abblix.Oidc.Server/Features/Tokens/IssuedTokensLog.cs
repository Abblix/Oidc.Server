// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Records who was handed which tokens, once the response carrying them is final: the tokens, the client and the
/// subject they were issued to, the grant they come from, and the scope and audiences they carry.
/// </summary>
/// <remarks>
/// The subject is named by the fingerprint of the end user's own identifier, the one every client of the user shares,
/// rather than by a pairwise pseudonym a token may carry instead, so one user's tokens are found together; no token
/// value is written. The fingerprint is keyed by <see cref="Common.Configuration.OidcOptions.FingerprintKey"/>, and
/// without it by a key of the process, so fingerprints match across nodes and restarts only where the deployment sets
/// one.
/// </remarks>
/// <param name="logger">The logger of the processor whose response is recorded.</param>
/// <param name="fingerprints">Stands for the subject in the record.</param>
internal sealed partial class IssuedTokensLog(ILogger logger, CredentialFingerprints fingerprints)
{
    /// <summary>
    /// Records the tokens a token request is answered with, whatever grant brought it, a CIBA push delivery included.
    /// </summary>
    /// <param name="tenant">The tenant the tokens are issued at.</param>
    /// <param name="request">The request answered.</param>
    /// <param name="response">The tokens it is answered with, whose access token names the refresh token family they
    /// belong to, when there is one.</param>
    public void AtTokenEndpoint(TenantDefinition tenant, ValidTokenRequest request, TokenIssued response)
    {
        var accessToken = response.AccessToken.Token.Payload;
        LogTokensIssued(
            tenant.Id,
            [
                TelemetryTokenTypes.AccessToken,
                ..response.RefreshToken is not null ? [TelemetryTokenTypes.RefreshToken] : Array.Empty<string>(),
                ..response.IdToken is not null ? [TelemetryTokenTypes.IdToken] : Array.Empty<string>(),
            ],
            request.ClientInfo.ClientId,
            fingerprints.Of(request.AuthorizedGrant.AuthSession.Subject),
            request.Model.GrantType,
            accessToken.GrantId,
            Sanitized.Values(accessToken.Scope),
            Sanitized.Values(accessToken.Audiences));
    }

    /// <summary>
    /// Records the tokens an authorization response hands out through the front channel, under the implicit grant the
    /// protocol names for them, the hybrid flow's included; a response carrying only a code is not recorded, since a
    /// code is redeemed, and recorded, at the token endpoint.
    /// </summary>
    /// <param name="tenant">The tenant the tokens are issued at.</param>
    /// <param name="request">The request answered.</param>
    /// <param name="authSession">The end user's session the tokens are issued for.</param>
    /// <param name="response">The response carrying the tokens.</param>
    public void ThroughFrontChannel(
        TenantDefinition tenant,
        ValidAuthorizationRequest request,
        AuthSession authSession,
        SuccessfullyAuthenticated response)
    {
        if (response is { AccessToken: null, IdToken: null })
            return;

        LogFrontChannelTokensIssued(
            tenant.Id,
            [
                ..response.AccessToken is not null ? [TelemetryTokenTypes.AccessToken] : Array.Empty<string>(),
                ..response.IdToken is not null ? [TelemetryTokenTypes.IdToken] : Array.Empty<string>(),
            ],
            request.ClientInfo.ClientId,
            fingerprints.Of(authSession.Subject),
            GrantTypes.Implicit,
            Sanitized.Values(response.GrantedScopes),
            Sanitized.Values(AudiencesOf(response.AccessToken)));
    }

    private static IEnumerable<string> AudiencesOf(EncodedJsonWebToken? accessToken)
        => accessToken?.Token.Payload.Audiences ?? [];
}
