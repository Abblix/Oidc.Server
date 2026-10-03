// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.MultiTenancy;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// A store of tenants held in memory that the server both reads and writes, as a host's database would be.
/// </summary>
internal sealed class MemoryTenantStore : ITenantStore, ITenantStoreWriter
{
    private readonly ConcurrentDictionary<string, StoredTenant> _tenants = new(StringComparer.Ordinal);

    public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyCollection<StoredTenant>>(_tenants.Values.ToArray());

    public Task<string?> AddAsync(TenantDefinition tenant, CancellationToken cancellationToken)
    {
        var stored = new StoredTenant(tenant, NewVersion());
        return Task.FromResult(_tenants.TryAdd(tenant.Id, stored) ? stored.Version : null);
    }

    public Task<string?> UpdateAsync(
        TenantDefinition tenant,
        string expectedVersion,
        CancellationToken cancellationToken)
    {
        if (!_tenants.TryGetValue(tenant.Id, out var current) || current.Version != expectedVersion)
            return Task.FromResult<string?>(null);

        var stored = new StoredTenant(tenant, NewVersion());
        return Task.FromResult(_tenants.TryUpdate(tenant.Id, stored, current) ? stored.Version : null);
    }

    public Task<bool> RemoveAsync(string tenantId, string expectedVersion, CancellationToken cancellationToken)
        => Task.FromResult(
            _tenants.TryGetValue(tenantId, out var current)
            && current.Version == expectedVersion
            && _tenants.TryRemove(new KeyValuePair<string, StoredTenant>(tenantId, current)));

    private static string NewVersion() => Guid.NewGuid().ToString("N");
}
