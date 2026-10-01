// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Refuses a tenant declaring keys its server's placement never reads, and, with the keys held by a
/// custodian, a tenant naming no key there or one another tenant names; with the keys minted by the server, a tenant
/// whose id cannot name its part of the store.
/// </summary>
/// <remarks>
/// Whether a tenant whose keys come from its settings declares enough of them is judged with the rest of its
/// settings, by the checks of the server's settings (<see cref="TenantSettingsCheck"/>).
/// </remarks>
/// <param name="serviceProvider">The container the key provider is resolved from, once the settings are built.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantKeysCheck(IServiceProvider serviceProvider) : ITenantsCheck
{
    /// <inheritdoc />
    public IEnumerable<TenantRefusal> Check(IReadOnlyCollection<TenantDefinition> tenants)
        => serviceProvider.GetService<IAuthServiceKeysProvider>() switch
        {
            OidcOptionsKeysProvider => Unread(tenants, "the keys come from each tenant's settings",
                nameof(TenantDefinition.SigningKeys), nameof(TenantDefinition.EncryptionKeys)),

            ExternalKeysProvider => Unread(tenants, "the keys are held by a custodian",
                    nameof(TenantDefinition.CustodianKeys))
                .Concat(CustodianKeysOf(tenants)),

            MintedKeysProvider => Unread(tenants, "the server mints the keys")
                .Concat(PartitionsOf(tenants)),

            // A key provider of the host's own is refused under multi-tenancy by the check of the registries
            _ => [],
        };

    /// <summary>
    /// The key settings a tenant declares that the placement never reads: declared, they read as the keys the
    /// tenant produces with while it produces with others.
    /// </summary>
    private static IEnumerable<TenantRefusal> Unread(IReadOnlyCollection<TenantDefinition> tenants, string placement, params string[] read)
        =>
            from tenant in tenants
            from setting in Declared(tenant)
            where !read.Contains(setting, StringComparer.Ordinal)
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': {nameof(TenantDefinition)}.{setting} is declared, but {placement}, " +
                "so it is never read.");

    private static IEnumerable<string> Declared(TenantDefinition tenant)
    {
        if (tenant.SigningKeys.Count > 0)
            yield return nameof(TenantDefinition.SigningKeys);
        if (tenant.EncryptionKeys.Count > 0)
            yield return nameof(TenantDefinition.EncryptionKeys);
        if (tenant.CustodianKeys is not null)
            yield return nameof(TenantDefinition.CustodianKeys);
    }

    /// <summary>
    /// Each tenant names keys in the custodian, and no key is named by two tenants: sharing one would let a party
    /// trusting one tenant's keys verify the other's tokens, which keys of their own exist to prevent.
    /// </summary>
    private static IEnumerable<TenantRefusal> CustodianKeysOf(IReadOnlyCollection<TenantDefinition> tenants)
    {
        var unnamed =
            from tenant in tenants
            where tenant.CustodianKeys is null
            select TenantRefusal.Of(tenant, $"Tenant '{tenant.Id}': {ExternalKeysProvider.NoKeyNamed}");

        // A tenant may name one key for both roles, so each tenant counts once per key
        var shared =
            from tenant in tenants
            where tenant.CustodianKeys is not null
            from keyName in new[] { tenant.CustodianKeys!.SigningKeyName, tenant.CustodianKeys.EncryptionKeyName }
                .Distinct(StringComparer.Ordinal)
            where keyName is not null
            group tenant.Id by keyName into namers
            where namers.Count() > 1
            select new TenantRefusal(
                [..namers],
                $"The custodian key '{namers.Key}' is named by the tenants " +
                $"{string.Join(", ", namers.Select(id => $"'{id}'"))}; each tenant produces with keys of its own.");

        return unnamed.Concat(shared);
    }

    /// <summary>
    /// The server keeps each tenant's minted keys in the store under its id and generation, joined by a separator
    /// the id may not hold, so the id must be a name the key ring accepts and must not spell another tenant's
    /// partition.
    /// </summary>
    private static IEnumerable<TenantRefusal> PartitionsOf(IReadOnlyCollection<TenantDefinition> tenants)
        =>
            from tenant in tenants
            where !TenantKey.IsPartitionSegment(tenant.Id)
            select TenantRefusal.Of(
                tenant,
                $"Tenant '{tenant.Id}': the server mints the keys and keeps each tenant's in the store under its " +
                "id, so the id may hold only letters, digits, '-' and '_'.");
}
