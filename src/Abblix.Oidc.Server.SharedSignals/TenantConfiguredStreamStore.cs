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
/// are built and reconciled the first time the tenant is asked for its streams, so the issuer and poll address of a
/// declared stream are the tenant's. Each creation of a tenant keeps a store of its own, let go once the creation is
/// released, built from the definition the server's own catalog has in force rather than from the one the request
/// holds, and built again when that definition moves the tenant to another issuer. With a catalog of the host's own,
/// which has no definition in force, the store is built from the first definition that asks and kept.
/// <para>
/// Every part of the store served for a tenant deletes a stream it creates after the tenant's creation is released
/// (<see cref="ReleaseCheckingStreamStore"/>), so a write still under way at the release leaves nothing behind.
/// </para>
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
    /// <summary>A creation's store of declared streams, and the issuer it was built for.</summary>
    private sealed record Built(string Issuer, Lazy<IStreamStore> Store);

    private readonly ConcurrentDictionary<string, Built> _stores = new(StringComparer.Ordinal);

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

    /// <summary>
    /// The store the current tenant is served, built as its first request would build it.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The tenant declares a stream no request could be served from.</exception>
    internal IStreamStore ForCurrentTenant() => Current;

    private IStreamStore Current
    {
        get
        {
            var tenant = tenantAccessor.CurrentTenant();
            var released = StoreTenantCatalog.ReleasedOf(catalog, tenant);
            var own = new ReleaseCheckingStreamStore(inner, released);

            // A released creation's declared streams are deleted as the streams it kept, and declaring them again
            // for a request still holding it would leave them with nobody to delete them
            if (declared.Of(tenant.Id) is not { } streams || released.IsCancellationRequested)
                return own;

            return catalog is StoreTenantCatalog served && served.InForce(tenant) is { } inForce
                ? DeclaredStore(TenantKey.SpaceOf(tenant), inForce, true, streams, own, released)
                : DeclaredStore(TenantKey.SpaceOf(tenant), tenant, false, streams, own, released);
        }
    }

    /// <summary>
    /// The store of declared streams of the creation <paramref name="space"/>, built from <paramref name="builtFrom"/>
    /// when it has none, or when <paramref name="inForce"/> says that definition is the one in force and the store
    /// was built for another issuer.
    /// </summary>
    private IStreamStore DeclaredStore(
        string space,
        TenantDefinition builtFrom,
        bool inForce,
        IReadOnlyList<ConfiguredStream> streams,
        IStreamStore own,
        CancellationToken released)
    {
        var issuer = builtFrom.Issuer.OriginalString;
        while (true)
        {
            var built = _stores.GetValueOrDefault(space);
            if (built is not null && (!inForce || built.Issuer == issuer))
                return built.Store.Value;

            var created = new Built(issuer, new Lazy<IStreamStore>(() => Build(builtFrom, streams, own)));
            if (Installed(space, built, created, released))
                return created.Store.Value;
        }
    }

    /// <summary>
    /// Puts <paramref name="created"/> in place of <paramref name="replaced"/>, or of nothing, unless another call got
    /// there first; a store put in place of nothing is let go once the creation is released.
    /// </summary>
    private bool Installed(string space, Built? replaced, Built created, CancellationToken released)
    {
        if (replaced is not null)
            return _stores.TryUpdate(space, created, replaced);

        if (!_stores.TryAdd(space, created))
            return false;

        released.Register(() => _stores.TryRemove(space, out _));
        return true;
    }

    /// <summary>
    /// The store of the streams <paramref name="tenant"/> declares, naming its issuer and poll address.
    /// </summary>
    private IStreamStore Build(TenantDefinition tenant, IReadOnlyList<ConfiguredStream> streams, IStreamStore own)
    {
        using var scope = TenantScope.Enter(tenant);
        return serviceProvider.CreateService<ConfigurationStreamStore>(
            Dependency.Override(streams),
            Dependency.Override(own));
    }
}
