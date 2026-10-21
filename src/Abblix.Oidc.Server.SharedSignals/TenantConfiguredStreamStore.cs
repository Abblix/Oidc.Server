// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Serves the streams a tenant declares in configuration as a <see cref="ConfigurationStreamStore"/> of that tenant,
/// reconciled into the tenant's own part of the store; a tenant declaring none is served the store as it is.
/// </summary>
/// <remarks>
/// The declared streams are the tenant's stream set, as they are the server's in a store of declared streams: they
/// are built and reconciled the first time the tenant is asked for its streams, inside the tenant, so the poll address
/// of a declared stream is the tenant's. Each creation of a tenant keeps a store of its own, let go once the creation
/// is released.
/// </remarks>
/// <param name="inner">The store each tenant's part of is kept apart in.</param>
/// <param name="declared">The streams each tenant declares.</param>
/// <param name="tenantAccessor">Names the tenant of the current request or scope.</param>
/// <param name="catalog">Tells when a creation of a tenant is released.</param>
/// <param name="serviceProvider">Builds a tenant's store of declared streams.</param>
internal sealed class TenantConfiguredStreamStore(
    IStreamStore inner,
    TenantConfiguredStreams declared,
    ITenantAccessor tenantAccessor,
    ITenantCatalog catalog,
    IServiceProvider serviceProvider) : IStreamStore
{
    private readonly ConcurrentDictionary<string, Lazy<IStreamStore>> _stores = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => Current.TryCreateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public Task<StreamState?> FindAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => Current.FindAsync(receiverId, streamId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAsync(string receiverId, CancellationToken cancellationToken = default)
        => Current.ListAsync(receiverId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
        => Current.ListAllAsync(cancellationToken);

    /// <inheritdoc />
    public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => Current.UpdateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => Current.DeleteAsync(receiverId, streamId, cancellationToken);

    private IStreamStore Current
    {
        get
        {
            var tenant = tenantAccessor.CurrentTenant();
            if (declared.Of(tenant.Id) is not { } streams)
                return inner;

            var space = TenantKey.SpaceOf(tenant);
            if (_stores.TryGetValue(space, out var store))
                return store.Value;

            var created = new Lazy<IStreamStore>(() => serviceProvider.CreateService<ConfigurationStreamStore>(
                Dependency.Override(streams),
                Dependency.Override(inner)));

            store = _stores.GetOrAdd(space, created);
            if (ReferenceEquals(store, created))
                StoreTenantCatalog.ReleasedOf(catalog, tenant).Register(() => _stores.TryRemove(space, out _));

            return store.Value;
        }
    }
}
