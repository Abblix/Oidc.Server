// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.TokenExchange;

/// <summary>
/// <see cref="ISubjectTokenResolver"/> for the <c>urn:ietf:params:oauth:token-type:refresh_token</c>
/// subject type. Refresh tokens issued by this AS are JWT-formatted with <c>typ=rt+jwt</c>; the
/// resolver validates the JWT, enforces the typ header, and recovers the original
/// <see cref="Endpoints.Token.Interfaces.AuthorizedGrant"/> via
/// <see cref="IRefreshTokenService.AuthorizeByRefreshTokenAsync"/>. The grant's subject, scope,
/// and <c>authorization_details</c> become the exchanged token's starting point.
/// </summary>
/// <remarks>
/// Unlike <see cref="JwtSubjectTokenResolver"/>, this implementation also touches refresh-token
/// storage -- the wire-level string by itself is not enough to recover the issued scope and AD,
/// since the JWT's payload carries only the identifying minimum (jti, exp, sub). A token already superseded by a
/// rotation is refused here as in the refresh_token grant, its family revoked with it, but the exchange spends no
/// token: it issues no refresh token to rotate into.
/// </remarks>
/// <param name="jwtValidator">Reads the refresh token: first that it is authentic, then, once the requesting client
/// is found entitled to present it, what is recorded about it.</param>
/// <param name="refreshTokenService">Resolves the JWT to the original authorised grant.</param>
/// <param name="cutoffChecker">Asks whether a revocation refuses the session the refresh token continues, as the
/// refresh grant asks.</param>
public sealed class RefreshTokenSubjectTokenResolver(
    IAuthServiceJwtReader jwtValidator,
    IRefreshTokenService refreshTokenService,
    IRevocationCutoffChecker cutoffChecker) : ISubjectTokenResolver
{
    /// <inheritdoc/>
    public async Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        TenantDefinition tenant,
        ClientInfo client,
        IClientInfoProvider clients,
        [Credential] string subjectToken,
        Uri tokenType,
        CancellationToken cancellationToken)
    {
        // A refresh token issued by 3.0 holds the resources of the grant it continues in its audience
        // (RefreshTokenResources), so the audience need not name this server
        var validation = await ReadAsync(tenant, client, clients, subjectToken);
        if (!validation.TryGetSuccess(out var jwt))
            return validation.GetFailure();

        // The refresh token was issued to its original client (not necessarily the requesting one); the real
        // subject is opened against that client's sector.
        var originalClientId = jwt.OwnerOf();
        ClientInfo? originalClient = null;
        if (originalClientId is null ||
            !(await clients.FindClientAsync(tenant, originalClientId)).TryGetSuccess(out originalClient))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The token's client is not known.");
        }

        if (RefusalOf(originalClient, jwt) is { } refusal)
            return refusal;

        var grantLookup = await refreshTokenService.AuthorizeByRefreshTokenAsync(tenant, jwt, originalClient);
        if (!grantLookup.TryGetSuccess(out var grant))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The token does not refer to a known grant.");
        }

        // The question the refresh grant asks of the same refresh token, so a token that grant refuses is not
        // exchanged instead: the validation above judges the token by its issue time, while a revocation dated after
        // the sign-in but before the family began refuses the session only by its authentication time.
        if (await cutoffChecker.IsGrantRefusedAsync(tenant, grant, GrantTypes.RefreshToken))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The session the token was issued in has been revoked.");
        }

        // DeepClone detaches AuthorizationDetails / Actor from the recovered grant's storage
        // instance so mutations downstream do not leak back into stored state.
        var authorizationDetails = (JsonArray?)grant.Context.AuthorizationDetails?.DeepClone();
        var act = (JsonObject?)grant.Context.Actor?.DeepClone();

        // The token's binding travels with it, for the token endpoint to require of the client it was issued to
        return new SubjectTokenContext(
            Subject: grant.AuthSession.Subject,
            Issuer: jwt.Payload.Issuer,
            Scope: grant.Context.Scope,
            AuthorizationDetails: authorizationDetails)
        {
            Act = act,

            // The client the token belongs to, which the handler's cross-client guard judges as it does here
            OriginalClientId = originalClientId,

            GrantId = jwt.Payload.GrantId,
            ExpiresAt = jwt.Payload.ExpiresAt,
            SessionId = grant.AuthSession.SessionId,
            AuthenticationTime = grant.AuthSession.AuthenticationTime,
            IdentityProvider = grant.AuthSession.IdentityProvider,
            AuthContextClassRef = grant.AuthSession.AuthContextClassRef,
            AuthenticationMethodReferences = grant.AuthSession.AuthenticationMethodReferences?.ToList(),
        }.BoundAs(jwt.Payload);
    }

    /// <summary>
    /// Why <paramref name="refreshToken"/> of <paramref name="originalClient"/> is not exchanged, or null when it may be.
    /// </summary>
    private static OidcError? RefusalOf(ClientInfo originalClient, JsonWebToken refreshToken)
    {
        // A refresh token exists only for offline access, so withdrawing its client's permission ends it here as it
        // does for the refresh grant; otherwise the token would keep buying access tokens until it expires
        if (!originalClient.OfflineAccess.IsAllowed())
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The token's client is not allowed offline access.");
        }

        // RFC 9700 section 2.2.2: a public client's refresh token is sender-constrained or rotated, and an exchange
        // rotates nothing, since it issues no refresh token, so a token that must rotate is not taken as a subject.
        // RFC 8693 section 2.2.2 answers a subject token "unacceptable based on policy" with invalid_request
        if (RefreshTokenRotationPolicy.MustRotate(originalClient, refreshToken.Payload))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The token is a public client's refresh token bound to no DPoP key, which is not exchanged.");
        }

        return null;
    }

    /// <summary>
    /// <paramref name="subjectToken"/> as a refresh token this server issued and still honors, which
    /// <paramref name="client"/> may present.
    /// </summary>
    private async Task<Result<JsonWebToken, OidcError>> ReadAsync(
        TenantDefinition tenant,
        ClientInfo client,
        IClientInfoProvider clients,
        string subjectToken)
    {
        var authentic = await jwtValidator.ReadAuthenticAsync(
            tenant,
            client,
            clients,
            subjectToken,
            TokenTypePolicy.Exactly(JwtTypes.RefreshToken),
            ServiceTokenValidation.AnyAudience);
        if (!authentic.TryGetSuccess(out var token))
            return InvalidToken;

        // The handler's cross-client guard, decided here before the token's records are read, because reading them
        // revokes the grant of a superseded refresh token, which a client holding another client's token would
        // otherwise do to it from here
        // A refresh token is addressed to this server alone, so it names no location of the presenting client,
        // whatever one issued by 3.0 holds in its audience
        if (TokenOrigin.CheckSubject(tenant, token.OwnerOf(), null, client) is { } refusal)
            return refusal;

        var recorded = await jwtValidator.ReadRecordsAsync(tenant, clients, token, ServiceTokenValidation.AnyAudience);
        return recorded.TryGetSuccess(out var valid) ? valid : InvalidToken;
    }

    /// <summary>
    /// The answer to a token that is not a refresh token this server issued and still honors.
    /// </summary>
    private static OidcError InvalidToken => new(ErrorCodes.InvalidRequest, "The token is invalid or has expired.");
}
