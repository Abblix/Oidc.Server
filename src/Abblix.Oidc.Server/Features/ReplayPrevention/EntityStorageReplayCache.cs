// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

/// <summary>
/// The server's replay cache, kept in the entity storage the server's other stores use, so a reservation is decided by
/// the storage's add-if-absent, as the end of a pushed authorization flow is.
/// </summary>
/// <remarks>
/// A host whose storage makes <see cref="IEntityStorage.TrySetIfAbsentAsync{T}"/> one command of a store every node
/// shares has the replay checks of every node right without a second implementation; over the shipped storage the
/// reservation is decided within one process, as the server's other single-use decisions are.
/// </remarks>
/// <param name="storage">The storage the server's stores use.</param>
/// <param name="clock">The clock the retention window is measured against.</param>
/// <param name="keyPrefix">The prefix of every reservation's key, the one <see cref="DistributedReplayCache"/>
/// writes under, so over the shipped storage the two read each other's reservations from one cache.</param>
internal sealed class EntityStorageReplayCache(IEntityStorage storage, TimeProvider clock, string keyPrefix)
    : ReplayCacheBase(clock, keyPrefix)
{
    /// <summary>
    /// What a reservation stores; only the presence of its key is read.
    /// </summary>
    private const string Marker = "reserved";

    /// <inheritdoc />
    /// <remarks>
    /// The entry expires when the reservation does, given as the time left until then, which the base class has
    /// already floored: an instant taken from this server's clock would be judged by the store's.
    /// </remarks>
    protected override Task<bool> ReserveIfAbsentAsync(
        string key,
        TimeSpan timeToLive,
        CancellationToken cancellationToken)
        => storage.TrySetIfAbsentAsync(
            key,
            Marker,
            new StorageOptions { AbsoluteExpirationRelativeToNow = timeToLive },
            cancellationToken);

    /// <inheritdoc />
    protected override Task RemoveAsync(string key, CancellationToken cancellationToken)
        => storage.RemoveAsync(key, cancellationToken);
}
