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
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// Refuses a second redemption of an authorization code, and revokes the tokens the first one issued, in
/// compliance with OAuth 2.0 security best practices. Two defenses, split by WHEN the repeat arrives
/// rather than by where: the claim refuses one arriving beside the first, and the issued tokens written
/// back at the key catch one arriving after it. Both hold across processes.
/// </summary>
/// <remarks>
/// How far the first defense reaches is the storage's answer, not this class's. <see cref="IEntityStorage"/>
/// requires a removing read to be indivisible, so a storage that keeps that promise across its nodes
/// hands the grant to exactly one caller however many instances are serving this endpoint. The storage
/// built over a distributed cache keeps it only within one process, where the read and the removal are
/// one hold of a per-key gate; a second instance sees no such gate, and both callers can be handed the
/// grant. Which storage is registered therefore decides whether this defense holds beyond one node.
/// <para>
/// The code is claimed only once the processor it wraps has issued tokens, so a request refused anywhere, the
/// processor included, leaves the code for the corrected one. The second defense rests on the write-back, which a
/// redemption makes only after its claim, so a reuse arriving between the two is refused without the first
/// redemption's tokens being revoked. The refusal this class returns is the same string either way.
/// </para>
/// <para>
/// This class decorates the standard token request processing flow with additional security measures
/// to ensure the integrity of the authorization process. It detects when an authorization code,
/// which should only be used once, is attempted to be used multiple times. In such cases, it revokes any
/// tokens previously issued with that code and denies the request, effectively mitigating potential
/// security risks associated with code reuse.
/// </para>
/// </remarks>
/// <param name="processor">The underlying token request processor to be enhanced.</param>
/// <param name="tokenRegistry">The registry used for managing token states and revocation.</param>
/// <param name="authorizationCodeService">
/// The service responsible for managing the lifecycle of authorization codes.</param>
/// <param name="grantRevocation">Revokes the refresh token family the first redemption founded.</param>
/// <param name="clock">The moment a reuse is caught, no earlier than the family's founding.</param>
public class AuthorizationCodeReusePreventingDecorator(
    ITokenRequestProcessor processor,
    ITokenRegistry tokenRegistry,
    IAuthorizationCodeService authorizationCodeService,
    GrantRevocation grantRevocation,
    TimeProvider clock): ITokenRequestProcessor
{
    /// <summary>
    /// Processes a valid token request, including revoking existing tokens if necessary and registering new tokens.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="request">The valid token request to process.</param>
    /// <returns>
    /// A task that returns a <see cref="TokenIssued"/> on success or an <see cref="OidcError"/> on failure.
    /// </returns>
    public async Task<Result<TokenIssued, OidcError>> ProcessAsync(TenantDefinition tenant, ValidTokenRequest request)
    {
        if (request is not { Model: { GrantType: GrantTypes.AuthorizationCode, Code: {} code } })
        {
            return await processor.ProcessAsync(tenant, request);
        }

        // A code a redemption already issued tokens for is reused, whatever else the request would be answered with,
        // so it is refused and what was issued is revoked before anything else is decided
        if (request.AuthorizedGrant.IssuedTokens is { Length: > 0 })
        {
            return await ClaimAsync(tenant, code, request.ClientInfo) ?? AlreadyUsed();
        }

        // The code is claimed only once tokens are issued for it, so a refusal of the processor - a resource the
        // token cannot be encrypted to, a scope narrowed to none - leaves the code for the corrected request, as a
        // validator's refusal does. Issuing writes nothing, so a redemption losing the claim drops its tokens unseen.
        var result = await processor.ProcessAsync(tenant, request);
        if (!result.TryGetSuccess(out var tokenResponse))
        {
            return result;
        }

        if (await ClaimAsync(tenant, code, request.ClientInfo) is { } refusal)
        {
            return refusal;
        }

        // Register issued tokens as part of the authorization code grant
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
            // The family the refresh token founded is written back too, for a reuse to revoke it
            await authorizationCodeService.UpdateAuthorizationGrantAsync(
                tenant,
                code,
                request.AuthorizedGrant with
                {
                    IssuedTokens = issuedTokensList.ToArray(),
                    GrantId = tokenResponse.RefreshToken?.Token.Payload.GrantId,
                },
                request.ClientInfo.AuthorizationCodeExpiresIn);
        }

        return result;
    }

    /// <summary>
    /// Claims the code by removing it, refusing the request when the claim is not handed the grant, or is handed one
    /// a redemption already issued tokens for, which are then revoked.
    /// </summary>
    /// <returns>The refusal, or <c>null</c> once this request holds the code.</returns>
    private async Task<OidcError?> ClaimAsync(TenantDefinition tenant, [Credential] string code, ClientInfo client)
    {
        // Not atomically, whatever the store's method names suggest: the extension assembles the protocol from
        // separate Get, Set and Remove calls, and says so. Two concurrent redemptions of a valid code contend for a
        // single claim instead of both passing a stale "not yet used" check.
        var claim = await authorizationCodeService.RemoveAuthorizationCodeAsync(tenant, code);

        // The code did not come back. The claim answers with the grant only when this caller ran the protocol to the
        // end with its own claim still in the store, so everything short of that arrives here as one outcome, the
        // right answer for whatever arrived and a diagnosis for none of it: this redemption loses.
        if (!claim.TryGetSuccess(out var claimedGrant))
        {
            return AlreadyUsed();
        }

        // The claimed grant carries tokens from a prior successful redemption - a sequential reuse
        if (claimedGrant.IssuedTokens is { Length: > 0 } issuedTokens)
        {
            await RevokeAsync(tenant, issuedTokens, claimedGrant.GrantId, client);
            return AlreadyUsed();
        }

        return null;
    }

    private static OidcError AlreadyUsed() => new(ErrorCodes.InvalidGrant, "The authorization code was already used");

    /// <summary>
    /// Revokes what the first redemption of a reused code issued.
    /// </summary>
    /// <remarks>
    /// RFC 6749 section 4.1.2: the server "SHOULD revoke (when possible) all tokens previously issued based on that
    /// authorization code", which RFC 9700 section 4.2.4 repeats. Those include what the first redemption's refresh
    /// token was rotated into since, and the access tokens minted from it, so the family it founded is revoked with
    /// the tokens it issued. A grant that records no family has its own tokens revoked.
    /// </remarks>
    private async Task RevokeAsync(TenantDefinition tenant, TokenInfo[] issuedTokens, string? grantId, ClientInfo client)
    {
        foreach (var (jwtId, expiresAt) in issuedTokens)
        {
            await tokenRegistry.SetStatusAsync(tenant, jwtId, JsonWebTokenStatus.Revoked, expiresAt);
        }

        // The family was founded at the first redemption, which is no later than now
        if (grantId is { Length: > 0 })
        {
            await grantRevocation.RevokeAsync(
                tenant, grantId, client, clock.GetUtcNow(), issuedTokens.Max(token => token.ExpiresAt));
        }
    }
}
