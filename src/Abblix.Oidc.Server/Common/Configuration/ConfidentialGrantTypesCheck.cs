// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses a tenant declaring a client that authenticates with <c>none</c> and may use a grant type kept for
/// confidential clients (<see cref="ConfidentialGrantTypes"/>), such as client credentials, which RFC 6749 section 4.4
/// says "MUST only be used by confidential clients".
/// </summary>
/// <remarks>
/// The token endpoint refuses such a client every such request; refusing it here as well tells the deployment when it
/// starts, rather than with the first request the client makes.
/// </remarks>
internal sealed class ConfidentialGrantTypesCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => Failures(tenant.Clients));

    private static IEnumerable<string> Failures(IEnumerable<ClientInfo> clients)
        =>
            from client in clients
            let refused = ConfidentialGrantTypes.RefusedTo(client.TokenEndpointAuthMethod, client.EffectiveGrantTypes)
            where refused.Length > 0
            select $"Client '{client.ClientId}' may use {string.Join(", ", refused)} but authenticates with " +
                   $"'{client.TokenEndpointAuthMethod}'; these grant types are only for a client that authenticates " +
                   "itself.";
}
