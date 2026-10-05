// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.MultiTenancy;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// A store of tenants the manager of the tenants writes to, held in memory.
/// </summary>
internal sealed class WritableTenantStore : ITenantStore, ITenantStoreWriter
{
    private readonly Dictionary<string, StoredTenant> _tenants = new(StringComparer.Ordinal);
    private int _versions;

    public IReadOnlyCollection<StoredTenant> Tenants => [.._tenants.Values];

    public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
        => Task.FromResult(Tenants);

    public Task<string?> AddAsync(TenantDefinition tenant, CancellationToken cancellationToken)
    {
        if (_tenants.ContainsKey(tenant.Id))
            return Task.FromResult<string?>(null);

        var version = (++_versions).ToString(CultureInfo.InvariantCulture);
        _tenants[tenant.Id] = new StoredTenant(tenant, version);
        return Task.FromResult<string?>(version);
    }

    public Task<string?> UpdateAsync(
        TenantDefinition tenant,
        string expectedVersion,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("The tests of the license only create tenants.");

    public Task<bool> RemoveAsync(string tenantId, string expectedVersion, CancellationToken cancellationToken)
        => throw new NotSupportedException("The tests of the license only create tenants.");
}
