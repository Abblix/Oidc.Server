// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using Abblix.DependencyInjection;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Builds the ring of each partition over its view of the shared store, once, and hands out the same ring to
/// everyone asking for that partition - the refresh loop that keeps it current included.
/// </summary>
/// <param name="serviceProvider">Constructs each ring.</param>
/// <param name="policy">What every ring mints, and the key-encryption key sealing it.</param>
/// <param name="store">The store every partition shares.</param>
/// <param name="partitions">The partitions to keep.</param>
internal sealed class KeyRings(
    IServiceProvider serviceProvider,
    MintedKeys policy,
    IKeyRingStore store,
    IKeyRingPartitions partitions) : IKeyRings
{
    private readonly ConcurrentDictionary<string, KeyRing> _rings = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public IKeyRing For(string partition) => Ring(partition);

    /// <inheritdoc />
    public async Task OpenAsync(string partition, CancellationToken cancellationToken)
    {
        if (!KeyRingOptions.IsPartitionName(partition))
        {
            throw new ArgumentException(
                $"'{partition}' cannot name a partition: its name goes in front of its entries' ids in the store, " +
                "so it holds only letters, digits, '-', '_' and '~'.",
                nameof(partition));
        }

        if (_rings.ContainsKey(partition))
            return;

        // Kept only once refreshed, so a ring whose first key could not be minted is built again on the next try
        // rather than served empty
        var ring = Build(partition);
        await ring.RefreshAsync(cancellationToken);
        _rings.TryAdd(partition, ring);
    }

    /// <summary>
    /// Starts a refresh round: the ring of every partition kept, each with its view of one read of the store taken
    /// for this round alone.
    /// </summary>
    public IReadOnlyList<(string Partition, KeyRing Ring, IKeyRingStore Source)> BeginRound()
    {
        var round = new KeyRingStoreRound(store);
        return partitions.Kept
            .Select(partition => (
                partition,
                Ring(partition),
                (IKeyRingStore)new PartitionedKeyRingStore(round, partition)))
            .ToArray();
    }

    /// <summary>
    /// The ring of <paramref name="partition"/>, built on first use.
    /// </summary>
    /// <remarks>
    /// A ring already built is served whether or not its partition is still kept: a request that began while its
    /// issuer was served finishes with that issuer's keys rather than failing for want of them.
    /// </remarks>
    public KeyRing Ring(string partition)
        => _rings.TryGetValue(partition, out var built) ? built : _rings.GetOrAdd(Kept(partition), Build);

    /// <summary>
    /// <paramref name="partition"/>, when the ring keeps it.
    /// </summary>
    private string Kept(string partition)
    {
        var kept = partitions.Kept;
        if (kept.Contains(partition, StringComparer.Ordinal))
            return partition;

        // The unnamed ring is what code written for a ring of one partition asks for
        throw new InvalidOperationException(partition == KeyRingOptions.DefaultPartition
            ? $"The key ring keeps {Listed(kept)} and no unnamed one, so there is no single {nameof(IKeyRing)} to " +
              $"serve: take the ring of one of its partitions from {nameof(IKeyRings)}.{nameof(IKeyRings.For)}."
            : $"The key ring keeps no partition '{partition}'; it keeps {Listed(kept)}.");
    }

    private static string Listed(IReadOnlyCollection<string> kept) => kept.Count == 0
        ? "no partitions"
        : "the partitions " + string.Join(", ", kept.Select(partition => $"'{partition}'"));

    private KeyRing Build(string partition)
    {
        // Adopted keys would be seeded into every ring, so each partition would serve the others' keys, and only
        // the unnamed partition is sure to be the ring's one
        if (partition != KeyRingOptions.DefaultPartition && policy.AdoptedKeys.Count > 0)
        {
            throw new InvalidOperationException(
                $"Existing keys are adopted into a key ring, and its partition '{partition}' is named, so other " +
                "partitions may come beside it: the same keys would be seeded into each, letting a party trusting " +
                "one partition's keys verify another's tokens. Adopt keys only into the unnamed partition of a " +
                "ring serving one issuer.");
        }

        return serviceProvider.CreateService<KeyRing>(
            Dependency.Override(policy),
            Dependency.Override<IKeyRingStore>(new PartitionedKeyRingStore(store, partition)));
    }
}
