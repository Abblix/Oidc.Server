// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Creates, changes and removes the tenants a store holds while the server runs, refusing a change the server's
/// startup checks would refuse, so a tenant is never stored in a form the server would leave out.
/// </summary>
/// <remarks>
/// Each change is judged against the tenants the store holds then and written through the store's
/// <see cref="ITenantStoreWriter"/>. This instance then reads the store again to serve it at once; should that
/// reading fail, or a created tenant not be readied to be served, it serves the change from its next reading that
/// succeeds, and other instances serve it at their next reading. A change written is reported as made either way.
/// <para>
/// The changes of one instance are made one at a time. Two instances changing tenants at once may each pass the
/// checks and together leave the store holding two tenants the checks refuse, such as two at one address: the
/// readings then leave both out and log why, as for any tenant the store holds that the checks refuse.
/// </para>
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public interface ITenantManager
{
    /// <summary>
    /// Creates <paramref name="tenant"/> under a new generation, so nothing kept for an earlier tenant of its id
    /// carries over to it.
    /// </summary>
    /// <param name="tenant">The tenant to create; its generation is assigned here.</param>
    /// <param name="cancellationToken">Cancels the change until it is written; after that it only stops the wait for
    /// this instance to serve the change, which is then reported as made.</param>
    /// <returns>The tenant as stored, or why it was refused.</returns>
    /// <exception cref="InvalidOperationException">The store registers no <see cref="ITenantStoreWriter"/>.
    /// </exception>
    Task<Result<StoredTenant, TenantChangeRefusal>> CreateAsync(
        TenantDefinition tenant,
        CancellationToken cancellationToken);

    /// <summary>
    /// Replaces the tenant stored under the id of <paramref name="tenant"/>, keeping its generation, while it is
    /// stored at <paramref name="version"/>.
    /// </summary>
    /// <param name="tenant">The tenant as it is to be; a generation it names is not taken, the stored one is kept.
    /// </param>
    /// <param name="version">The version the tenant was read at.</param>
    /// <param name="cancellationToken">Cancels the change until it is written; after that it only stops the wait for
    /// this instance to serve the change, which is then reported as made.</param>
    /// <returns>The tenant as stored, or why it was refused.</returns>
    /// <exception cref="InvalidOperationException">The store registers no <see cref="ITenantStoreWriter"/>.
    /// </exception>
    Task<Result<StoredTenant, TenantChangeRefusal>> UpdateAsync(
        TenantDefinition tenant,
        string version,
        CancellationToken cancellationToken);

    /// <summary>
    /// Removes the tenant stored under <paramref name="tenantId"/>, while it is stored at
    /// <paramref name="version"/>.
    /// </summary>
    /// <param name="tenantId">The id of the tenant to remove.</param>
    /// <param name="version">The version the tenant was read at.</param>
    /// <param name="cancellationToken">Cancels the change until it is written; after that it only stops the wait for
    /// this instance to serve the change, which is then reported as made.</param>
    /// <returns>The tenant as it was stored, or why the removal was refused.</returns>
    /// <exception cref="InvalidOperationException">The store registers no <see cref="ITenantStoreWriter"/>.
    /// </exception>
    Task<Result<StoredTenant, TenantChangeRefusal>> RemoveAsync(
        string tenantId,
        string version,
        CancellationToken cancellationToken);
}
