// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Removes the entries of partitions from the store, each partition on its own, over one read of the store.
/// </summary>
/// <param name="setup">The store every partition shares.</param>
internal sealed class KeyRingEntriesRemoval(KeyRingSetup setup)
{
    /// <inheritdoc cref="IKeyRings.DeleteAsync"/>
    public async Task<IReadOnlyDictionary<string, Exception>> DeleteAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken)
    {
        var round = new KeyRingStoreRound(setup.Store);
        var failures = new Dictionary<string, Exception>(StringComparer.Ordinal);
        foreach (var partition in partitions)
        {
            try
            {
                // Stopped, the partitions not reached yet keep their entries, and asking the store for them would
                // not end sooner
                cancellationToken.ThrowIfCancellationRequested();

                var entries = new PartitionedKeyRingStore(round, partition);
                foreach (var entry in await entries.LoadAsync(cancellationToken))
                    await entries.RemoveAsync(entry.Id, cancellationToken);
            }
            catch (Exception exception)
            {
                failures[partition] = exception;
            }
        }

        return failures;
    }
}
