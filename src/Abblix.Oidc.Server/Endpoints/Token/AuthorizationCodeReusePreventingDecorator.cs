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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Enhances token processing by revoking tokens associated with previously used authorization codes,
/// preventing authorization code reuse in compliance with OAuth 2.0 security best practices.
/// </summary>
/// <remarks>
/// This class decorates the standard token request processing flow with additional security measures
/// to ensure the integrity of the authorization process. It detects when an authorization code,
/// which should only be used once, is attempted to be used multiple times. In such cases, it revokes any
/// tokens previously issued with that code and denies the request, effectively mitigating potential
/// security risks associated with code reuse.
/// </remarks>
/// <param name="processor">The underlying token request processor to be enhanced.</param>
/// <param name="tokenRegistry">The registry used for managing token states and revocation.</param>
/// <param name="authorizationCodeService">
/// The service responsible for managing the lifecycle of authorization codes.</param>
public class AuthorizationCodeReusePreventingDecorator(
    ITokenRequestProcessor processor,
    ITokenRegistry tokenRegistry,
    IAuthorizationCodeService authorizationCodeService): ITokenRequestProcessor
{
    /// <summary>
    /// Processes a valid token request, including revoking existing tokens if necessary and registering new tokens.
    /// </summary>
    /// <param name="request">The valid token request to process.</param>
    /// <returns>
    /// A task that returns a <see cref="TokenIssued"/> on success or an <see cref="OidcError"/> on failure.
    /// </returns>
    public async Task<Result<TokenIssued, OidcError>> ProcessAsync(ValidTokenRequest request)
    {
        if (request is not { Model: { GrantType: GrantTypes.AuthorizationCode, Code: {} code } })
        {
            return await processor.ProcessAsync(request);
        }

        // Atomically claim the code by removing it (get-and-remove). This happens AFTER the grant
        // validators have already checked client binding and PKCE, so a failed validation never
        // reaches here and never burns the code - but two concurrent redemptions of a valid code
        // now contend for a single claim instead of both passing a stale "not yet used" check.
        var claim = await authorizationCodeService.RemoveAuthorizationCodeAsync(code);

        // The code did not come back. What can reach this: a competitor claimed it between validation
        // and here, the entry's lifetime lapsed in that same window, or a claim expired mid-protocol -
        // the last two needing no second request at all. What cannot: a code already consumed, because
        // AuthorizeByCodeAsync reads the entry non-destructively and refuses before a consumed code ever
        // becomes a valid request, and ORDINARY sequential reuse is caught by the next branch instead. Nor
        // a store call that failed after the removal, which raises rather than answering. The refusal
        // below is the right one for every case that does arrive, and a diagnosis for none.
        // Whichever of them it was, this redemption loses - reject without issuing a second set.
        if (!claim.TryGetSuccess(out var claimedGrant))
        {
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The authorization code was already used");
        }

        // The claimed grant carries tokens from a prior successful redemption - a sequential reuse.
        // Revoke those tokens (OAuth 2.0 Security BCP section 4.13) and reject.
        if (claimedGrant.IssuedTokens is { Length: > 0 } issuedTokens)
        {
            foreach (var (jwtId, expiresAt) in issuedTokens)
            {
                await tokenRegistry.SetStatusAsync(jwtId, JsonWebTokenStatus.Revoked, expiresAt);
            }

            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The authorization code was already used");
        }

        // We won the claim - proceed with processing the request using the decorated processor.
        var result = await processor.ProcessAsync(request);

        // Register issued tokens as part of the authorization code grant
        if (result.TryGetSuccess(out var tokenResponse))
        {
            var issuedTokensList = new List<TokenInfo>();

            void TryRegisterToken(JsonWebToken? token)
            {
                if (token is { Payload: { JwtId: { } jwtId, ExpiresAt: { } expiresAt }})
                {
                    issuedTokensList.Add(new TokenInfo(jwtId, expiresAt));
                }
            }

            TryRegisterToken(tokenResponse.AccessToken.Token);
            TryRegisterToken(tokenResponse.RefreshToken?.Token);

            if (issuedTokensList.Count > 0)
            {
                await authorizationCodeService.UpdateAuthorizationGrantAsync(
                    code,
                    request.AuthorizedGrant with { IssuedTokens = issuedTokensList.ToArray() },
                    request.ClientInfo.AuthorizationCodeExpiresIn);
            }
        }

        return result;
    }
}
