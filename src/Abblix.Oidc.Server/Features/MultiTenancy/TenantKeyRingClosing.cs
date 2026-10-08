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
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Deletes from the key ring's store the keys the server minted for a released tenant.
/// </summary>
/// <remarks>
/// The partition belongs to that creation of the tenant alone, so a tenant created again under the same id, which
/// mints into a partition of its own generation, keeps its keys. A released tenant whose id or generation could not
/// name a partition of its own was never opened, and the partition its name spells may be another tenant's, so
/// nothing is deleted for it. Keys from the settings or a custodian are not the server's to delete. The ring of the
/// partition was already let go when the tenant was released. The ring and the minting are resolved when a tenant is
/// closed, as <see cref="TenantKeyRingOpening"/> resolves them when it is opened.
/// </remarks>
/// <param name="serviceProvider">Resolves the key ring and tells whether the server mints its keys.</param>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public sealed class TenantKeyRingClosing(IServiceProvider serviceProvider) : ITenantClosing
{
    /// <inheritdoc />
    public Task CloseAsync(TenantDefinition tenant, CancellationToken cancellationToken)
    {
        if (serviceProvider.GetService<IAuthServiceKeysProvider>() is not MintedKeysProvider)
            return Task.CompletedTask;

        if (!NamesItsOwnPartition(tenant))
            return Task.CompletedTask;

        return serviceProvider.GetRequiredService<IKeyRings>()
            .DeleteAsync(TenantKey.PartitionOf(tenant), cancellationToken);
    }

    private static bool NamesItsOwnPartition(TenantDefinition tenant)
        => TenantKey.IsPartitionSegment(tenant.Id) &&
           (tenant.Generation.Length == 0 || TenantKey.IsPartitionSegment(tenant.Generation));
}
