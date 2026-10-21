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

        // A tenant's id holds no separator of its generation, so each creation of each tenant names a partition
        // of its own
        var alone = tenants.ToDictionary(TenantKey.PartitionOf, StringComparer.Ordinal);

        var rings = serviceProvider.GetRequiredService<IKeyRings>();
        var failures = await rings.OpenAsync(alone.Keys, cancellationToken);

        var catalog = serviceProvider.GetRequiredService<ITenantCatalog>();
        foreach (var (partition, tenant) in alone.Where(opened => !failures.ContainsKey(opened.Key)))
        {
            if (_watched.TryAdd(partition, default))
                StoreTenantCatalog.ReleasedOf(catalog, tenant).Register(() => Close(rings, partition));
        }

        return failures.ToDictionary(
            failure => alone[failure.Key].Id,
            failure => failure.Value,
            StringComparer.Ordinal);
    }

    private void Close(IKeyRings rings, string partition)
    {
        _watched.TryRemove(partition, out _);
        rings.Close(partition);
    }
}
