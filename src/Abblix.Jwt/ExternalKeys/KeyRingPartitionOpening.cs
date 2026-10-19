// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Readies the ring of one partition to serve: builds it when it is not built yet and refreshes it when it is not
/// current, which mints a first key where none is due.
/// </summary>
/// <param name="rings">The rings built so far.</param>
/// <param name="options">The refresh period an opened ring stays current for.</param>
/// <param name="timeProvider">When an opening happens.</param>
internal sealed class KeyRingPartitionOpening(
    KeyRingRegistry rings,
    IOptions<KeyRingOptions> options,
    TimeProvider timeProvider)
{
    /// <summary>
    /// Whether the ring of <paramref name="partition"/> is built and current: kept, or opened within half a refresh
    /// period.
    /// </summary>
    /// <remarks>
    /// Half a period, because a ring opened but not yet kept waits for the loop's next round once it is kept: opened
    /// within the window and kept at its end, it is refreshed again within one and a half periods, short of the
    /// propagation window a pod must not miss a new key for.
    /// </remarks>
    public bool IsCurrent(string partition)
        => rings.IsCurrent(partition, options.Value.RefreshPeriod / 2, timeProvider.GetUtcNow());

    /// <summary>
    /// Builds the ring of <paramref name="partition"/> when it is not built yet and refreshes it from
    /// <paramref name="round"/>.
    /// </summary>
    public async Task OpenAsync(string partition, KeyRingStoreRound round, CancellationToken cancellationToken)
    {
        if (!KeyRingOptions.IsPartitionName(partition))
        {
            throw new ArgumentException(
                $"'{partition}' cannot name a partition: its name goes in front of its entries' ids in the store, " +
                "so it holds only letters, digits, '-', '_' and '~'.",
                nameof(partition));
        }

        // Kept only once refreshed, so a ring whose first key could not be minted is built again on the next try
        // rather than served empty
        var ring = rings.Built(partition);
        await ring.RefreshAsync(new PartitionedKeyRingStore(round, partition), cancellationToken);
        rings.Keep(partition, ring, timeProvider.GetUtcNow());
    }
}
