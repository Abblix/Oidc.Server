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
using Abblix.Oidc.Server.Features.Tokens.Validation;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Whether a registration access token (RFC 7592) is in force: it is while the registration of the client it names
/// still holds its identifier, and every reader of the token asks here.
/// </summary>
/// <remarks>
/// This server binds each registration to the identifier (jti) of the one token managing it. Registration and an update
/// give the registration a new identifier, so the token an update replaces is discarded, as RFC 7592 appendix A.1 has
/// the server do with a rotated token "if possible"; a read issues a token under the identifier the registration holds.
/// A revocation (<see cref="RegistrationAccessTokenRevocation"/>) binds the registration to an identifier no token
/// carries, and the registration is gone with the client, which invalidates its token as RFC 7592 sections 2.3 and 5
/// require of a deprovisioned client. So the registration is the whole record of the token. A client the store serves from the settings has no
/// registration, and no token is in force for it.
/// </remarks>
/// <param name="clientInfoManager">Holds each registration with the identifier of the token managing it.</param>
public sealed class RegistrationAccessTokenBinding(IClientInfoManager clientInfoManager)
{
    /// <summary>
    /// The registration <paramref name="registrationAccessToken"/> manages, or null when it manages none.
    /// </summary>
    /// <param name="tenant">The tenant the token is validated for, whose registrations are read.</param>
    /// <param name="registrationAccessToken">A registration access token this server issued, found authentic.</param>
    public Task<RegisteredClient?> FindRegistrationAsync(TenantDefinition tenant, JsonWebToken registrationAccessToken)
    {
        if (registrationAccessToken is not { Payload.JwtId: { } tokenId } ||
            registrationAccessToken.OwnerOf() is not { } clientId)
        {
            return Task.FromResult<RegisteredClient?>(null);
        }

        return FindRegistrationAsync(tenant, clientId, tokenId);
    }

    /// <summary>
    /// The registration of <paramref name="clientId"/> while it is managed by the token <paramref name="tokenId"/>
    /// identifies, or null.
    /// </summary>
    /// <param name="tenant">The tenant the registration is looked up at.</param>
    /// <param name="clientId">The client the token names.</param>
    /// <param name="tokenId">The identifier (jti) of the token.</param>
    public async Task<RegisteredClient?> FindRegistrationAsync(TenantDefinition tenant, string clientId, string tokenId)
    {
        var registration = await clientInfoManager.TryFindRegisteredClientAsync(tenant, clientId);
        return registration?.RegistrationAccessTokenId == tokenId ? registration : null;
    }
}
