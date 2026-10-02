// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Opens the part of the key ring each tenant signs with when the server mints its keys, minting its first key, so a
/// tenant the store gains while the server runs has a key from its first request.
/// </summary>
/// <remarks>
/// Which keys the server signs with is decided where the host places them, so it is read when tenants are opened
/// rather than at registration; keys from the settings or a custodian need no opening.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantKeyRingOpening(IServiceProvider serviceProvider) : ITenantOpening
{
    // The partitions whose ring is closed when their tenant is released, each registered once however often it is
    // opened again
    private readonly ConcurrentDictionary<string, byte> _watched = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<TenantDefinition> tenants,
        CancellationToken cancellationToken)
    {
        if (serviceProvider.GetService<IAuthServiceKeysProvider>() is not MintedKeysProvider)
            return new Dictionary<string, Exception>();

        // Tenants opened together that share a partition would sign with each other's keys, so none of them is
        // opened; across the whole list the checks of the tenant list refuse such tenants
        var byPartition = tenants.ToLookup(TenantKey.PartitionOf, StringComparer.Ordinal);
        var shared = byPartition.Where(sharing => sharing.Count() > 1).ToArray();
        var alone = byPartition.Where(sharing => sharing.Count() == 1).ToDictionary(
            sharing => sharing.Key,
            sharing => sharing.Single(),
            StringComparer.Ordinal);

        var rings = serviceProvider.GetRequiredService<IKeyRings>();
        var failures = await rings.OpenAsync(alone.Keys, cancellationToken);

        var catalog = serviceProvider.GetRequiredService<ITenantCatalog>();
        foreach (var (partition, tenant) in alone.Where(opened => !failures.ContainsKey(opened.Key)))
        {
            if (_watched.TryAdd(partition, default))
                StoreTenantCatalog.ReleasedOf(catalog, tenant).Register(() => Close(rings, partition));
        }

        return failures
            .Select(failure => (alone[failure.Key].Id, failure.Value))
            .Concat(
                from sharing in shared
                from tenant in sharing
                select (tenant.Id, (Exception)new InvalidOperationException(
                    $"Tenant '{tenant.Id}' shares the key ring partition '{sharing.Key}' with another tenant.")))
            .ToDictionary(failure => failure.Item1, failure => failure.Item2, StringComparer.Ordinal);
    }

    private void Close(IKeyRings rings, string partition)
    {
        _watched.TryRemove(partition, out _);
        rings.Close(partition);
    }
}
