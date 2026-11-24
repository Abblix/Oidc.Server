// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Revokes the grant a refresh token was issued under, so every token issued under it, refresh and access tokens
/// alike, is refused.
/// </summary>
/// <remarks>
/// The mark lasts until the last moment any token of the grant could still be valid, not until the expiry of the
/// token that revoked it: a refresh token issued later under the same grant expires later, and would be accepted
/// again once a shorter mark was forgotten. Every refresh token of a grant carries the grant's first issuance as its
/// issue time, and none outlives that by more than its client's absolute refresh token lifetime; an access token
/// issued from the last of them lives one access token lifetime longer, and one exchanged from a token of the grant
/// expires no later than that token. A client whose lifetimes were shortened after tokens were issued can leave a
/// token outliving the mark; the presented token's own expiry is the floor.
/// </remarks>
/// <param name="tokenRegistry">Records the grant as revoked.</param>
/// <param name="clientInfoProvider">Finds the client whose refresh and access token lifetimes bound the grant.</param>
public sealed class GrantRevocation(ITokenRegistry tokenRegistry, IClientInfoProvider clientInfoProvider)
{
    /// <summary>
    /// Revokes the grant <paramref name="refreshToken"/> was issued under; a token naming no grant revokes nothing.
    /// </summary>
    /// <param name="tenant">The tenant the token is validated for, whose records are read.</param>
    /// <param name="refreshToken">The payload of a refresh token of the grant.</param>
    public async Task RevokeAsync(TenantDefinition tenant, JsonWebTokenPayload refreshToken)
    {
        if (refreshToken is not { GrantId: { } grantId, ExpiresAt: { } expiresAt })
            return;

        var ceiling = await LastValidMomentAsync(tenant, refreshToken);
        await RevokeUntilAsync(tenant, grantId, ceiling, expiresAt);
    }

    /// <summary>
    /// Revokes the grant <paramref name="grantId"/> of <paramref name="client"/>, first issued no later than
    /// <paramref name="issuedNoLaterThan"/>, when no refresh token of it is at hand.
    /// </summary>
    /// <param name="tenant">The tenant the grant belongs to.</param>
    /// <param name="grantId">The grant to revoke.</param>
    /// <param name="client">The client the grant was issued to, whose lifetimes bound its tokens.</param>
    /// <param name="issuedNoLaterThan">A moment no earlier than the grant's first issuance.</param>
    /// <param name="expiresAt">The latest expiry among the known tokens of the grant, the floor of the mark.</param>
    public Task RevokeAsync(
        TenantDefinition tenant,
        string grantId,
        ClientInfo client,
        DateTimeOffset issuedNoLaterThan,
        DateTimeOffset expiresAt)
        => RevokeUntilAsync(tenant, grantId, LastValidMoment(client, issuedNoLaterThan), expiresAt);

    private Task RevokeUntilAsync(TenantDefinition tenant, string grantId, DateTimeOffset? ceiling, DateTimeOffset floor)
        => tokenRegistry.SetStatusAsync(
            tenant,
            grantId,
            JsonWebTokenStatus.Revoked,
            ceiling is { } value && value > floor ? value : floor);

    /// <summary>
    /// The last moment any token of the grant, refresh or access, could still be valid, or null when the grant's
    /// first issuance or its client cannot be found, in which case the presented token's own expiry is the best
    /// known bound.
    /// </summary>
    private async Task<DateTimeOffset?> LastValidMomentAsync(TenantDefinition tenant, JsonWebTokenPayload refreshToken)
    {
        if (refreshToken is not { IssuedAt: { } issuedAt, ClientId: { } clientId })
            return null;

        return (await clientInfoProvider.FindClientAsync(tenant, clientId)).TryGetSuccess(out var client)
            ? LastValidMoment(client, issuedAt)
            : null;
    }

    private static DateTimeOffset LastValidMoment(ClientInfo client, DateTimeOffset issuedAt)
        => issuedAt + client.RefreshToken.AbsoluteExpiresIn + client.AccessTokenExpiresIn;
}
