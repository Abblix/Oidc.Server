// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Starts the refresh rounds of the partitions kept.
/// </summary>
/// <param name="rings">The ring of each partition.</param>
/// <param name="setup">The partitions to keep.</param>
/// <param name="store">The store every partition shares.</param>
internal sealed class KeyRingRounds(KeyRingRegistry rings, KeyRingSetup setup, IKeyRingStore store)
{
    /// <summary>
    /// Starts a refresh round: the ring of every partition kept, each with its view of one read of the store taken
    /// for this round alone.
    /// </summary>
    /// <param name="exceptOpened">Leaves out the partitions refreshed when they were opened, as the round the
    /// ring starts with does.</param>
    public IReadOnlyList<(string Partition, KeyRing Ring, IKeyRingStore Source)> BeginRound(bool exceptOpened = false)
    {
        var round = new KeyRingStoreRound(store);
        return setup.PartitionsKept.Kept
            .Where(partition => !exceptOpened || !rings.WasOpened(partition))
            .Select(partition => (
                partition,
                rings.Ring(partition),
                (IKeyRingStore)new PartitionedKeyRingStore(round, partition)))
            .ToArray();
    }
}
