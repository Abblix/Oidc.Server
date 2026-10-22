// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client that may use backchannel authentication without authenticating itself.
/// </summary>
/// <remarks>
/// CIBA Core 1.0 sections 7.1 and 10.1 have the client authenticate at both endpoints of the flow, and both endpoints
/// refuse a client registered with the method "none". Refusing it here as well tells the deployment when it starts,
/// rather than with the first request such a client makes.
/// </remarks>
public sealed class BackChannelClientAuthenticationCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => Failures(tenant.Clients));

    private static IEnumerable<string> Failures(IEnumerable<ClientInfo> clients)
        =>
            from client in clients
            where client is { ClientType: ClientType.Public } && client.EffectiveGrantTypes.Contains(GrantTypes.Ciba)
            select $"Client '{client.ClientId}' may use backchannel authentication but authenticates with " +
                   $"'{client.TokenEndpointAuthMethod}'; the flow requires a client that authenticates itself.";
}
