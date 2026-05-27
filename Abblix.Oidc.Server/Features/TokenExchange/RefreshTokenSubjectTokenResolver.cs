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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
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
public sealed class RefreshTokenSubjectTokenResolver(
    IAuthServiceJwtValidator jwtValidator,
    IRefreshTokenService refreshTokenService) : ISubjectTokenResolver
{
    /// <inheritdoc/>
    public string Type => TokenExchangeTokenTypes.RefreshToken;

    /// <inheritdoc/>
    public async Task<Result<SubjectTokenContext, OidcError>> ResolveAsync(
        string subjectToken,
        CancellationToken cancellationToken)
    {
        var validation = await jwtValidator.ValidateAsync(subjectToken);
        if (!validation.TryGetSuccess(out var jwt))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The subject_token is invalid or has expired.");
        }

        if (jwt.Header.Type != JwtTypes.RefreshToken)
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                $"subject_token has unexpected typ header '{jwt.Header.Type}' for token type refresh_token.");
        }

        var grantLookup = await refreshTokenService.AuthorizeByRefreshTokenAsync(jwt);
        if (!grantLookup.TryGetSuccess(out var grant))
        {
            return new OidcError(ErrorCodes.InvalidRequest, "The subject_token does not refer to a known grant.");
        }

        // DeepClone detaches AuthorizationDetails / Actor from the recovered grant's storage
        // instance so mutations downstream do not leak back into stored state.
        var authorizationDetailsRaw =
            grant.Context.AuthorizationDetails is { } ad
                ? (JsonArray?)ad.DeepClone()
                : null;

        var act =
            grant.Context.Actor is { } existingAct
                ? (JsonObject?)existingAct.DeepClone()
                : null;

        return new SubjectTokenContext(
            Subject: grant.AuthSession.Subject,
            Issuer: grant.AuthSession.IdentityProvider,
            Scope: grant.Context.Scope,
            AuthorizationDetailsRaw: authorizationDetailsRaw,
            Act: act);
    }
}
