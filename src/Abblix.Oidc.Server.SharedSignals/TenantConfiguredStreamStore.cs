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
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Serves the streams a tenant declares in configuration as a <see cref="ConfigurationStreamStore"/> of that tenant,
/// reconciled into the tenant's own part of the store; a tenant declaring none is served its part of the store.
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
/// (<see cref="ReleaseCheckingStreamStore"/>), so a write still under way at the release leaves nothing behind
/// unless that deletion fails, which is logged. A
/// store of declared streams that another has replaced writes nothing more
/// (<see cref="SupersededWritesRefusedStreamStore"/>), so its reconcile cannot bring back the issuer the tenant left.
/// </para>
/// </remarks>
/// <param name="logger">Records a stream written after its tenant's release that could not be deleted.</param>
/// <param name="inner">The store each tenant's part of is kept apart in.</param>
/// <param name="declared">The streams each tenant declares.</param>
/// <param name="tenantAccessor">Names the tenant of the current request or scope.</param>
/// <param name="catalog">Tells when a creation of a tenant is released.</param>
/// <param name="serviceProvider">Builds a tenant's store of declared streams.</param>
internal sealed class TenantConfiguredStreamStore(
    ILogger<TenantConfiguredStreamStore> logger,
    IStreamStore inner,
    TenantConfiguredStreams declared,
    ITenantAccessor tenantAccessor,
    ITenantCatalog catalog,
    IServiceProvider serviceProvider) : IStreamStore
{
    /// <summary>
    /// A creation's store of declared streams and the issuer it was built for, told apart from another by reference,
    /// as its backing store asks whether it is still the one installed.
    /// </summary>
    private sealed class Built
    {
        public Built(string space, string issuer, Func<Built, IStreamStore> build)
        {
            Space = space;
            Issuer = issuer;
            Store = new Lazy<IStreamStore>(() => build(this));
        }

        public string Space { get; }

        public string Issuer { get; }

        public Lazy<IStreamStore> Store { get; }
    }

    /// <summary>The store a call is served, and the store of declared streams it is, when it is one.</summary>
    private readonly record struct Serving(IStreamStore Store, Built? Declared);

    private readonly ConcurrentDictionary<string, Built> _stores = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => WrittenAsync(store => store.TryCreateAsync(stream, cancellationToken));

    /// <inheritdoc />
    public Task<StreamState?> FindAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => Current.Store.FindAsync(receiverId, streamId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAsync(string receiverId, CancellationToken cancellationToken = default)
        => Current.Store.ListAsync(receiverId, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
        => Current.Store.ListAllAsync(cancellationToken);

    /// <inheritdoc />
    public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
        => Current.Store.UpdateAsync(stream, cancellationToken);

    /// <inheritdoc />
    public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
        => WrittenAsync(store => store.DeleteAsync(receiverId, streamId, cancellationToken));

    /// <summary>
    /// Writes through the store the tenant is served, and again through the one it is served then for as long as the
    /// write is refused by a store of declared streams another replaced meanwhile, as a receiver's create or delete
    /// queued behind that store's reconcile is (<see cref="SupersededWritesRefusedStreamStore"/>).
    /// </summary>
    /// <remarks>
    /// Each further round follows a replacement made during this call, since a replaced store is never installed
    /// again, and a released creation is served no store of declared streams, so the rounds end.
    /// </remarks>
    private async Task<bool> WrittenAsync(Func<IStreamStore, Task<bool>> write)
    {
        var serving = Current;
        while (!await write(serving.Store))
        {
            if (serving.Declared is null || IsCurrent(serving.Declared))
                return false;

            serving = Current;
        }

        return true;
    }

    /// <summary>
    /// The store the current tenant is served, built as its first request would build it.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The tenant declares a stream no request could be served from.</exception>
    internal IStreamStore ForCurrentTenant() => Current.Store;

    private Serving Current
    {
        get
        {
            var tenant = tenantAccessor.CurrentTenant();
            var released = StoreTenantCatalog.ReleasedOf(catalog, tenant);
            var own = new ReleaseCheckingStreamStore(logger, inner, released, TenantKey.PartitionOf(tenant));

            // A released creation is served its part of the store alone: building its declared store again would
            // reconcile, writing the declared streams its release is deleting, and would do so on every call of the
            // release's own cleanup, which goes through here
            if (declared.Of(tenant.Id) is not { } streams || released.IsCancellationRequested)
                return new Serving(own, null);

            var built = catalog is StoreTenantCatalog served && served.InForce(tenant) is { } inForce
                ? DeclaredStore(TenantKey.SpaceOf(tenant), inForce, true, streams, own, released)
                : DeclaredStore(TenantKey.SpaceOf(tenant), tenant, false, streams, own, released);

            return new Serving(built.Store.Value, built);
        }
    }

    /// <summary>
    /// The store of declared streams of the creation <paramref name="space"/>, built from <paramref name="builtFrom"/>
    /// when it has none, or when <paramref name="inForce"/> says that definition is the one in force and the store
    /// was built for another issuer.
    /// </summary>
    private Built DeclaredStore(
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
                return built;

            var created = new Built(
                space,
                issuer,
                installed => Build(
                    builtFrom,
                    streams,
                    new SupersededWritesRefusedStreamStore(own, () => IsCurrent(installed))));
            if (Installed(space, built, created, released))
                return created;
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
    /// Whether <paramref name="built"/> is still the store of declared streams its creation is served.
    /// </summary>
    private bool IsCurrent(Built built)
        => _stores.TryGetValue(built.Space, out var current) && ReferenceEquals(current, built);

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
