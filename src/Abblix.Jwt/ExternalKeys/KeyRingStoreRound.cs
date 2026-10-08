// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The store every partition shares, read once for one round: each partition refreshed or opened in the round
/// takes the same read, a write the round won is added to it, and a write another pod won makes the next load read
/// the store again. A round lives only as long as one pass of the refresh service, one opening of partitions or one
/// deletion of partitions, so nothing it read outlives that pass.
/// </summary>
/// <remarks>
/// Every backend reads each entry's body to load, so a read per partition would cost the number of partitions
/// times the number of entries on every tick, and an entry the backend cannot read would be read, and fail, once
/// per partition.
/// </remarks>
/// <param name="store">The store every partition shares.</param>
internal sealed class KeyRingStoreRound(IKeyRingStore store) : IKeyRingStore
{
    private IReadOnlyList<StoredKey>? _entries;

    /// <inheritdoc />
    /// <remarks>
    /// Only a completed read is kept: a load that failed leaves the next partition to read for itself.
    /// </remarks>
    public async Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
        => _entries ??= await store.LoadAsync(cancellationToken);

    /// <inheritdoc />
    /// <remarks>
    /// A write this round won keeps the round's read, the entry added to it, so the partitions it opens or
    /// refreshes one after another share one read of the store. A write another pod won, or one that failed, leaves
    /// the store holding what this round has not seen, so the next load reads it again.
    /// </remarks>
    public async Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken)
    {
        bool added;
        try
        {
            added = await store.TryAddAsync(key, cancellationToken);
        }
        catch
        {
            _entries = null;
            throw;
        }

        _entries = added && _entries is { } read ? [..read, key] : null;
        return added;
    }

    /// <inheritdoc />
    /// <remarks>
    /// The round's read is kept: a partition removes only its own entries, as the last step of its refresh or when
    /// it is deleted, and no other partition reads them.
    /// </remarks>
    public Task RemoveAsync(string id, CancellationToken cancellationToken)
        => store.RemoveAsync(id, cancellationToken);
}
