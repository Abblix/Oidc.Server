// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Writes to a store of tenants, for a host that changes its tenants through <see cref="ITenantManager"/>.
/// </summary>
/// <remarks>
/// A store the host writes to by other means needs none. Each change of a stored tenant names the version it was
/// read at and is applied only while the store still holds that version, as one conditional write, so a change
/// made meanwhile by another instance is never overwritten unseen.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantStoreWriter
{
    /// <summary>
    /// Adds <paramref name="tenant"/>, unless the store holds a tenant under its id already.
    /// </summary>
    /// <param name="tenant">The tenant to add, its generation assigned.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>The version the tenant is stored at; null when the store holds a tenant under its id.</returns>
    Task<string?> AddAsync(TenantDefinition tenant, CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the tenant stored under the id of <paramref name="tenant"/>, while it is stored at
    /// <paramref name="expectedVersion"/>.
    /// </summary>
    /// <param name="tenant">The tenant as it is to be stored.</param>
    /// <param name="expectedVersion">The version the tenant was read at.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>The version the tenant is stored at now; null when it is stored at another version or not at all.
    /// </returns>
    Task<string?> UpdateAsync(TenantDefinition tenant, string expectedVersion, CancellationToken cancellationToken);

    /// <summary>
    /// Removes the tenant stored under <paramref name="tenantId"/>, while it is stored at
    /// <paramref name="expectedVersion"/>.
    /// </summary>
    /// <param name="tenantId">The id of the tenant to remove.</param>
    /// <param name="expectedVersion">The version the tenant was read at.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <returns>Whether the tenant was removed; false when it is stored at another version or not at all.</returns>
    Task<bool> RemoveAsync(string tenantId, string expectedVersion, CancellationToken cancellationToken);
}
