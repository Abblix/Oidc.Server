// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using Abblix.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Builds the ring of each partition over its view of the shared store, once, and hands out the same ring to
/// everyone asking for that partition - the refresh loop that keeps it current included.
/// </summary>
/// <param name="serviceProvider">Constructs each ring.</param>
/// <param name="policy">What every ring mints, and the key-encryption key sealing it.</param>
/// <param name="store">The store every partition shares.</param>
/// <param name="options">The partitions to keep.</param>
internal sealed class KeyRings(
    IServiceProvider serviceProvider,
    MintedKeys policy,
    IKeyRingStore store,
    IOptions<KeyRingOptions> options) : IKeyRings
{
    private readonly ConcurrentDictionary<string, KeyRing> _rings = new(StringComparer.Ordinal);
    private readonly KeyRingStoreRound _round = new(store);

    /// <inheritdoc />
    public IKeyRing For(string partition) => Ring(partition);

    /// <summary>
    /// Starts a refresh round: the rings refreshed in it share one read of the store, taken afresh.
    /// </summary>
    public void BeginRound() => _round.Begin();

    /// <summary>
    /// The ring of every partition kept.
    /// </summary>
    public IEnumerable<(string Partition, KeyRing Ring)> All
        => options.Value.Partitions.Select(partition => (partition, Ring(partition)));

    /// <summary>
    /// The ring of <paramref name="partition"/>, built on first use.
    /// </summary>
    public KeyRing Ring(string partition)
    {
        var partitions = options.Value.Partitions;
        if (partition == KeyRingOptions.DefaultPartition && !partitions.Contains(partition, StringComparer.Ordinal))
        {
            // Asked through IKeyRing, which names no partition, by code written for a ring serving one issuer
            throw new InvalidOperationException(
                $"The key ring keeps a partition for each issuer and none for a single one, so there is no one " +
                $"{nameof(IKeyRing)} to serve: take the ring of an issuer from {nameof(IKeyRings)}.{nameof(IKeyRings.For)}.");
        }

        if (!partitions.Contains(partition, StringComparer.Ordinal))
        {
            throw new InvalidOperationException(
                $"The key ring keeps no partition '{partition}'; it keeps {string.Join(", ", partitions.Select(kept => $"'{kept}'"))}.");
        }

        // Adopted keys would be seeded into every ring, so each partition would serve the others' keys
        if (partitions.Count > 1 && policy.AdoptedKeys.Count > 0)
        {
            throw new InvalidOperationException(
                "Existing keys are adopted into a key ring keeping several partitions, which would seed the same keys " +
                "into each and let a party trusting one partition's keys verify another's tokens. Adopt keys only " +
                "into a ring keeping one partition.");
        }

        return _rings.GetOrAdd(partition, kept => serviceProvider.CreateService<KeyRing>(
            Dependency.Override(policy),
            Dependency.Override<IKeyRingStore>(new PartitionedKeyRingStore(_round, kept))));
    }
}
