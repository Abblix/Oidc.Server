// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// The authenticated backchannel authentication request a grant was read from, consumed once tokens are issued for
/// it.
/// </summary>
/// <param name="redeemer">Consumes the request and judges the grant it consumed.</param>
/// <param name="processor">The processor of the client's delivery mode, which consumes the request.</param>
/// <param name="authenticationRequestId">The authentication request being redeemed.</param>
/// <param name="yardstick">What the request asked for, as read.</param>
internal sealed class BackChannelRequestRedemption(
    BackChannelGrantRedeemer redeemer,
    IBackChannelGrantProcessor processor,
    [Credential] string authenticationRequestId,
    BackChannelGrantYardstick yardstick) : ISingleUseRedemption
{
    /// <inheritdoc />
    public Task<OidcError?> SpendAsync(TenantDefinition tenant, ClientInfo clientInfo)
        => redeemer.ClaimAsync(tenant, authenticationRequestId, yardstick, clientInfo, processor);
}
