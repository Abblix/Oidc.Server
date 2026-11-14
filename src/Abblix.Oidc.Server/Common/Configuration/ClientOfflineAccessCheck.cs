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
/// Refuses a tenant declaring a client whose offline access is none of the values the enumeration names.
/// </summary>
/// <remarks>
/// Configuration binds a number to an enumeration whatever its value, so a mistyped one would otherwise reach the
/// server and fail every request of that client, on the request, with an error that names neither the client nor the
/// setting.
/// </remarks>
public sealed class ClientOfflineAccessCheck : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants, OidcOptions options)
        => TenantRefusal.EachOf(tenants, tenant => Failures(tenant.Clients));

    private static IEnumerable<string> Failures(IEnumerable<ClientInfo> clients)
        => clients
            .Where(client => !Enum.IsDefined(client.OfflineAccess))
            .Select(client =>
                $"The client '{client.ClientId}' is configured with {nameof(ClientInfo.OfflineAccess)} " +
                $"'{client.OfflineAccess}', which is none of {string.Join(", ", Enum.GetNames<OfflineAccess>())}.");
}
