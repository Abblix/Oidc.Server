// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// One partition's view of the store the partitions share: it reads only the partition's entries, and writes and
/// removes them under their ids with the partition name in front.
/// </summary>
/// <param name="store">The store every partition shares.</param>
/// <param name="partition">The partition, or <see cref="KeyRingOptions.DefaultPartition"/>, whose entries carry
/// no name in front and whose ids have no dot.</param>
internal sealed class PartitionedKeyRingStore(IKeyRingStore store, string partition) : IKeyRingStore
{
    private const char Separator = '.';

    private readonly string _prefix = partition.Length == 0 ? string.Empty : partition + Separator;

    private bool Owns(string storedId) => _prefix.Length == 0
        ? !storedId.Contains(Separator)
        : storedId.StartsWith(_prefix, StringComparison.Ordinal);

    /// <inheritdoc />
    public async Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
    {
        var entries = await store.LoadAsync(cancellationToken);
        return entries
            .Where(entry => Owns(entry.Id))
            .Select(entry => entry with { Id = entry.Id[_prefix.Length..] })
            .ToArray();
    }

    /// <inheritdoc />
    public Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken)
        => store.TryAddAsync(key with { Id = _prefix + key.Id }, cancellationToken);

    /// <inheritdoc />
    public Task RemoveAsync(string id, CancellationToken cancellationToken)
        => store.RemoveAsync(_prefix + id, cancellationToken);
}
