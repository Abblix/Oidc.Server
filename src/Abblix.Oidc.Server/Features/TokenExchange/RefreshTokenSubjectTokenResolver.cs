// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.Tokens;
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
/// since the JWT's payload carries only the identifying minimum (jti, exp, sub). The lookup
/// service additionally enforces single-use / rotation semantics in environments that opt in
/// to refresh-token rotation, so a token already redeemed will reject here exactly as it would
/// in the refresh_token grant.
/// </remarks>
/// <param name="jwtValidator">Validates the refresh-token JWT's signature and lifetime.</param>
/// <param name="refreshTokenService">Resolves the JWT to the original authorised grant.</param>
/// <param name="clientInfoProvider">Resolves the client the refresh token was issued to, whose sector opens a
/// pairwise subject back to the real subject.</param>
public sealed class RefreshTokenSubjectTokenResolver(
    IAuthServiceJwtValidator jwtValidator,
    IRefreshTokenService refreshTokenService,
    IClientInfoProvider clientInfoProvider) : ISubjectTokenResolver
{
    /// <inheritdoc/>
    public async Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        string subjectToken,
        CancellationToken cancellationToken)
    {
        var validation = await jwtValidator.ValidateAsync(subjectToken);
        if (!validation.TryGetSuccess(out var jwt))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The subject_token is invalid or has expired.");
        }

        if (jwt.Header.Type != JwtTypes.RefreshToken)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token has unexpected typ header '{jwt.Header.Type}' for token type refresh_token.");
        }

        // The refresh token was issued to its original client (not necessarily the requesting one); the real
        // subject is opened against that client's sector.
        var originalClientId = jwt.Payload.ClientId;
        var originalClient = originalClientId is null
            ? null
            : await clientInfoProvider.TryFindClientAsync(originalClientId).WithLicenseCheck();
        if (originalClient is null)
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The subject_token's client is not known.");
        }

        var grantLookup = await refreshTokenService.AuthorizeByRefreshTokenAsync(jwt, originalClient);
        if (!grantLookup.TryGetSuccess(out var grant))
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "The subject_token does not refer to a known grant.");
        }

        // DeepClone detaches AuthorizationDetails / Actor from the recovered grant's storage
        // instance so mutations downstream do not leak back into stored state.
        var authorizationDetails = (JsonArray?)grant.Context.AuthorizationDetails?.DeepClone();
        var act = (JsonObject?)grant.Context.Actor?.DeepClone();

        return new SubjectTokenContext(
            Subject: grant.AuthSession.Subject,
            Issuer: grant.AuthSession.IdentityProvider,
            Scope: grant.Context.Scope,
            AuthorizationDetails: authorizationDetails)
        {
            Act = act,

            // Origin tracking from the recovered grant -- the refresh_token's storage record
            // names the client it was issued to. Mismatch with the requesting client triggers
            // the handler's cross-client guard.
            OriginalClientId = grant.Context.ClientId,
            
            // Refresh tokens always have typ=rt+jwt (enforced above). Recording it here makes
            // the typ-confusion check at the handler uniform across resolvers.
            JwtTokenType = jwt.Header.Type,
        };
    }
}
