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
/// Refuses a tenant declaring two clients under one id, or under ids that differ only in the case of their letters.
/// </summary>
/// <remarks>
/// A request names a client by its id exactly, but no tenant holds two clients under ids differing only in case
/// (<see cref="ClientIdComparison.Held"/>), so the client registry cannot hold both and fails when it is first built -
/// on a request, with an error that names neither client.
/// </remarks>
public sealed class ClientIdsCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => Failures(tenant.Clients));

    private static IEnumerable<string> Failures(IEnumerable<ClientInfo> clients)
        => clients
            .GroupBy(client => client.ClientId, ClientIdComparison.Held)
            .Where(same => same.Count() > 1)
            .Select(same =>
                $"{same.Count()} clients are configured under the id " +
                $"{string.Join(" and ", same.Select(client => $"'{client.ClientId}'").Distinct())}; no two clients " +
                "may hold ids that differ only in case, so give each client an id of its own.");
}
