// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The refresh of one partition in a round: its ring, refreshed from its view of the round's read of the store.
/// </summary>
/// <param name="Partition">The partition refreshed.</param>
/// <param name="Ring">The ring of the partition.</param>
/// <param name="Source">The partition's view of the round's read of the store.</param>
internal readonly record struct KeyRingPartitionRefresh(string Partition, KeyRing Ring, IKeyRingStore Source)
{
    /// <summary>
    /// Refreshes the ring from its view of the store.
    /// </summary>
    public Task RefreshAsync(CancellationToken cancellationToken) => Ring.RefreshAsync(Source, cancellationToken);
}
