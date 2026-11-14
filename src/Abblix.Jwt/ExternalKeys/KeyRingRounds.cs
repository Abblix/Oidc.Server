// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Starts the refresh rounds of the partitions kept, one every refresh period.
/// </summary>
/// <param name="rings">The ring of each partition.</param>
/// <param name="setup">The partitions to keep and the store they share.</param>
/// <param name="options">How often a round starts.</param>
internal sealed class KeyRingRounds(KeyRingRegistry rings, KeyRingSetup setup, IOptions<KeyRingOptions> options)
{
    /// <summary>
    /// How long one round waits for the next.
    /// </summary>
    public TimeSpan Period => options.Value.RefreshPeriod;

    /// <summary>
    /// Starts a refresh round: the ring of every partition kept, each with its view of one read of the store taken
    /// for this round alone.
    /// </summary>
    /// <param name="exceptOpened">Leaves out the partitions refreshed when they were opened, as the round the
    /// ring starts with does.</param>
    public IReadOnlyList<KeyRingPartitionRefresh> BeginRound(bool exceptOpened = false)
    {
        var round = new KeyRingStoreRound(setup.Store);
        return setup.PartitionsKept.Kept
            .Where(partition => !exceptOpened || !rings.WasOpened(partition))
            .Select(partition => new KeyRingPartitionRefresh(
                partition,
                rings.Ring(partition),
                new PartitionedKeyRingStore(round, partition)))
            .ToArray();
    }
}
