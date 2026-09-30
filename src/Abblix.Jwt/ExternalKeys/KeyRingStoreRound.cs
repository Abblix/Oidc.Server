// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The store every partition shares, read once per refresh round: each partition's refresh in the round takes
/// the same read, and a write makes the next load read the store again.
/// </summary>
/// <remarks>
/// Every backend reads each entry's body to load, so a read per partition would cost the number of partitions
/// times the number of entries on every tick, and an entry the backend cannot read would be read, and fail, once
/// per partition.
/// </remarks>
/// <param name="store">The store every partition shares.</param>
internal sealed class KeyRingStoreRound(IKeyRingStore store) : IKeyRingStore
{
    private Task<IReadOnlyList<StoredKey>>? _entries;

    /// <summary>
    /// Starts a round: the next load reads the store afresh.
    /// </summary>
    public void Begin() => _entries = null;

    /// <inheritdoc />
    public Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
        => _entries ??= store.LoadAsync(cancellationToken);

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
            Begin();
        }
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string id, CancellationToken cancellationToken)
    {
        try
        {
            await store.RemoveAsync(id, cancellationToken);
        }
        finally
        {
            Begin();
        }
    }
}
