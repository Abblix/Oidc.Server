// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Builds the Shared Signals transmitter of each tenant and keeps it for as long as that creation of the tenant is
/// served.
/// </summary>
/// <remarks>
/// Each creation of a tenant has a transmitter of its own, let go once the creation is released, built from the
/// definition the server's own catalog has in force rather than from the one the caller holds, and built again when
/// that definition moves the tenant to another issuer. With a catalog of the host's own, which has no definition in
/// force, the transmitter is built from the first definition that asks and kept. A released creation is built a
/// transmitter on every call and kept nowhere, serving its part of the stores alone, so its release can delete its
/// streams without its declared streams being written again.
/// <para>
/// The stores, the outbox and the delivery lease the host registered are shared by every tenant: they hold the data,
/// which outlives a transmitter built again after a move. Each transmitter reaches its tenant's part of them through
/// the tenant's space, which names the tenant and its creation.
/// </para>
/// </remarks>
/// <param name="catalog">Tells when a creation of a tenant is released and which definition of it is in force.</param>
/// <param name="declared">The streams each tenant declares.</param>
/// <param name="logger">Records a write to a tenant's streams sent again after the tenant moved.</param>
/// <param name="builder">Builds each transmitter.</param>
internal sealed partial class TenantTransmitters(
    ILogger<TenantTransmitters> logger,
    ITenantCatalog catalog,
    TenantConfiguredStreams declared,
    TenantTransmitterBuilder builder)
{
    /// <summary>
    /// The key the stream store the host registered is kept under, shared by every tenant, while the unkeyed
    /// registration answers with the store of the tenant being served.
    /// </summary>
    internal const string SharedStoreKey = "Abblix.Oidc.Server.SharedSignals.StoreOfEveryTenant";

    /// <summary>
    /// A creation's transmitter and the issuer it was built for, told apart from another by reference, as its store
    /// of declared streams asks whether it is still the one installed.
    /// </summary>
    private sealed class Built
    {
        public Built(string space, string issuer, Func<Built, TenantTransmitter> build)
        {
            Space = space;
            Issuer = issuer;
            Transmitter = new Lazy<TenantTransmitter>(() => build(this));
        }

        public string Space { get; }

        public string Issuer { get; }

        public Lazy<TenantTransmitter> Transmitter { get; }
    }

    private readonly ConcurrentDictionary<string, Built> _built = new(StringComparer.Ordinal);

    private readonly Lazy<TenantTransmitter> _none = new(builder.BuildNone);

    /// <summary>
    /// The transmitter resolved where no tenant is served, whose parts refuse once they reach a tenant's data.
    /// </summary>
    public TenantTransmitter None => _none.Value;

    /// <summary>
    /// The transmitter of <paramref name="tenant"/>, built as its first request would build it.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The tenant declares a stream no request could be served from.</exception>
    public TenantTransmitter For(TenantDefinition tenant)
    {
        var released = StoreTenantCatalog.ReleasedOf(catalog, tenant);
        if (released.IsCancellationRequested)
            return builder.Build(tenant, released, declared: null);

        var (builtFrom, inForce) = catalog is StoreTenantCatalog served && served.InForce(tenant) is { } held
            ? (held, true)
            : (tenant, false);

        var space = TenantKey.SpaceOf(tenant);
        var issuer = builtFrom.Issuer.OriginalString;
        while (true)
        {
            var built = _built.GetValueOrDefault(space);
            if (built is not null && (!inForce || built.Issuer == issuer))
                return built.Transmitter.Value;

            var created = new Built(
                space,
                issuer,
                installed => builder.Build(builtFrom, released, Declaration(tenant, installed)));
            if (Installed(space, built, created, released))
                return created.Transmitter.Value;
        }
    }

    /// <summary>
    /// Puts <paramref name="created"/> in place of <paramref name="replaced"/>, or of nothing, unless another call got
    /// there first; a transmitter put in place of nothing is let go once the creation is released.
    /// </summary>
    private bool Installed(string space, Built? replaced, Built created, CancellationToken released)
    {
        if (replaced is not null)
            return _built.TryUpdate(space, created, replaced);

        if (!_built.TryAdd(space, created))
            return false;

        released.Register(() => _built.TryRemove(space, out _));
        return true;
    }

    /// <summary>
    /// The streams <paramref name="tenant"/> declares, as the transmitter <paramref name="installed"/> serves them, or
    /// null when it declares none.
    /// </summary>
    private TenantStreamDeclaration? Declaration(TenantDefinition tenant, Built installed)
        => declared.Of(tenant.Id) is { } streams
            ? new TenantStreamDeclaration(streams, () => IsCurrent(installed), new ServedStreams(logger, this, tenant))
            : null;

    /// <summary>
    /// Whether <paramref name="built"/> is still the transmitter its creation is served.
    /// </summary>
    private bool IsCurrent(Built built)
        => _built.TryGetValue(built.Space, out var current) && ReferenceEquals(current, built);

    /// <summary>
    /// The streams of a tenant that declares some, read and written through the store of the transmitter the tenant is
    /// served when each call is made.
    /// </summary>
    /// <remarks>
    /// A create or delete queued behind a reconcile of a store of declared streams another replaced meanwhile is
    /// refused by that store (<see cref="SupersededWritesRefusedStreamStore"/>), and made again through the store the
    /// tenant is served then. Each further round follows a replacement made during the call, since a replaced store is
    /// never installed again, and a released creation is served no store of declared streams, so the rounds end.
    /// </remarks>
    /// <param name="logger">Records a write sent again.</param>
    /// <param name="transmitters">Finds the transmitter the tenant is served.</param>
    /// <param name="tenant">The tenant whose streams these are.</param>
    private sealed class ServedStreams(ILogger logger, TenantTransmitters transmitters, TenantDefinition tenant)
        : IStreamStore
    {
        /// <inheritdoc />
        public Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => WrittenAsync(store => store.TryCreateAsync(stream, cancellationToken));

        /// <inheritdoc />
        public Task<StreamState?> FindAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
            => Store.FindAsync(receiverId, streamId, cancellationToken);

        /// <inheritdoc />
        public Task<IReadOnlyList<StreamState>> ListAsync(string receiverId, CancellationToken cancellationToken = default)
            => Store.ListAsync(receiverId, cancellationToken);

        /// <inheritdoc />
        public Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
            => Store.ListAllAsync(cancellationToken);

        /// <inheritdoc />
        public Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
            => Store.UpdateAsync(stream, cancellationToken);

        /// <inheritdoc />
        public Task<bool> DeleteAsync(string receiverId, string streamId, CancellationToken cancellationToken = default)
            => WrittenAsync(store => store.DeleteAsync(receiverId, streamId, cancellationToken));

        private IStreamStore Store => transmitters.For(tenant).Store;

        private async Task<bool> WrittenAsync(Func<IStreamStore, Task<bool>> write)
        {
            var serving = transmitters.For(tenant);
            while (!await write(serving.Store))
            {
                if (!serving.Superseded())
                    return false;

                serving = transmitters.For(tenant);
                LogWriteSentAgain(logger, tenant.Id, serving.Identity.Issuer);
            }

            return true;
        }
    }
}
