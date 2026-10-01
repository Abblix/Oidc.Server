// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The store every partition shares, read once for one refresh round: each partition's refresh in the round takes
/// the same read, and a write makes the next load read the store again. A round lives only as long as the refresh
/// service's pass over the partitions, so nothing it read outlives the pass.
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
    public async Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken)
    {
        try
        {
            return await store.TryAddAsync(key, cancellationToken);
        }
        finally
        {
            // Whether this write or another pod's won, the store changed since the round's read
            _entries = null;
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// The round's read is kept: a partition removes only its own entries, as the last step of its refresh, and
    /// no other partition reads them.
    /// </remarks>
    public Task RemoveAsync(string id, CancellationToken cancellationToken)
        => store.RemoveAsync(id, cancellationToken);
}
