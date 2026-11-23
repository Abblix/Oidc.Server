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
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.Tokens.Validation;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Revokes a registration access token (RFC 7592), so the client configuration endpoint refuses it from then on.
/// </summary>
/// <remarks>
/// The token carries no expiry: RFC 7592 section 5 has it not expire "while a client is still actively registered".
/// What it reaches is already decided by its registration, which holds the identifier of the one token managing it
/// and refuses every other, and loses it when the client is deleted. So the revocation is recorded there, by binding
/// the registration to an identifier no token carries: it lasts exactly as long as the client, and no record of it
/// outlives the client. A revoked token leaves the client without a token for its registration, which RFC 7592
/// appendix A.1 warns of; the client asked for it.
/// </remarks>
/// <param name="clientInfoManager">Holds each registration with the identifier of the token managing it.</param>
/// <param name="tokenIdGenerator">Generates the identifier no token carries.</param>
public sealed class RegistrationAccessTokenRevocation(
    IClientInfoManager clientInfoManager,
    ITokenIdGenerator tokenIdGenerator)
{
    /// <summary>
    /// Revokes <paramref name="registrationAccessToken"/> where it still manages its registration; a token already
    /// replaced, or whose client is gone, manages nothing and is left as it is.
    /// </summary>
    /// <param name="tenant">The tenant the token is validated for, whose registrations are read.</param>
    /// <param name="registrationAccessToken">A registration access token this server issued, found authentic.</param>
    public async Task RevokeAsync(TenantDefinition tenant, JsonWebToken registrationAccessToken)
    {
        if (registrationAccessToken is not { Payload.JwtId: { } tokenId } ||
            registrationAccessToken.OwnerOf() is not { } clientId)
        {
            return;
        }

        var registration = await clientInfoManager.TryFindRegisteredClientAsync(tenant, clientId);
        if (registration is null || registration.RegistrationAccessTokenId != tokenId)
            return;

        // Taken only while the registration still holds the token: one the token was replaced on or removed from in
        // between has already ended it
        await clientInfoManager.TryUpdateClientAsync(
            tenant,
            registration,
            registration with { RegistrationAccessTokenId = tokenIdGenerator.GenerateTokenId() });
    }
}
