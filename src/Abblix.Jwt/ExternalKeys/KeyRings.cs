// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The rings of every partition (Facade): hands out the ring of each, opens partitions, closes them and removes
/// their entries from the store.
/// </summary>
/// <param name="rings">The ring of each partition.</param>
/// <param name="opening">Readies the rings of partitions to serve.</param>
/// <param name="removal">Removes the entries of partitions from the store.</param>
internal sealed class KeyRings(
    KeyRingRegistry rings,
    KeyRingPartitionsOpening opening,
    KeyRingEntriesRemoval removal) : IKeyRings
{
    /// <inheritdoc />
    public IKeyRing For(string partition) => rings.Ring(partition);

    /// <inheritdoc />
    public Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken)
        => opening.OpenAsync(partitions, cancellationToken);

    /// <inheritdoc />
    public void Close(string partition) => rings.Close(partition);

    /// <inheritdoc />
    public Task<IReadOnlyDictionary<string, Exception>> DeleteAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken)
        => removal.DeleteAsync(partitions, cancellationToken);
}
