// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using Abblix.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Builds the ring of each partition over its view of the shared store, once, and hands out the same ring to
/// everyone asking for that partition - the refresh loop that keeps it current included.
/// </summary>
/// <param name="serviceProvider">Constructs each ring.</param>
/// <param name="policy">What every ring mints, and the key-encryption key sealing it.</param>
/// <param name="store">The store every partition shares.</param>
/// <param name="partitionsKept">The partitions to keep.</param>
internal sealed class KeyRings(
    IServiceProvider serviceProvider,
    MintedKeys policy,
    IKeyRingStore store,
    IKeyRingPartitions partitionsKept) : IKeyRings
{
    private readonly ConcurrentDictionary<string, KeyRing> _rings = new(StringComparer.Ordinal);

    // When each partition was last refreshed by an opening: the refresh loop's first round need not refresh such a
    // partition again, and an opening soon after finds it current
    private readonly ConcurrentDictionary<string, DateTimeOffset> _openedAt = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public IKeyRing For(string partition) => Ring(partition);

    /// <inheritdoc />
    public void Close(string partition)
    {
        _rings.TryRemove(partition, out _);
        _openedAt.TryRemove(partition, out _);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken)
    {
        var kept = partitionsKept.Kept;
        var due = partitions.Where(partition => !IsCurrent(partition, kept)).ToArray();
        var round = new KeyRingStoreRound(store);
        var failures = new Dictionary<string, Exception>(StringComparer.Ordinal);
        for (var index = 0; index < due.Length; index++)
        {
            if (await FailureOfAsync(due[index], round, cancellationToken) is not { } failure)
                continue;

            failures[due[index]] = failure;
            if (cancellationToken.IsCancellationRequested)
            {
                // What was opened stays open, so the next opening goes on from where this one was stopped
                foreach (var unreached in due.Skip(index + 1))
                    failures[unreached] = failure;

                break;
            }
        }

        return failures;
    }

    /// <summary>
    /// Why opening <paramref name="partition"/> failed, or null when it opened.
    /// </summary>
    private async Task<Exception?> FailureOfAsync(
        string partition,
        KeyRingStoreRound round,
        CancellationToken cancellationToken)
    {
        try
        {
            await OpenAsync(partition, round, cancellationToken);
            return null;
        }
        catch (Exception exception)
        {
            return exception;
        }
    }

    /// <summary>
    /// Whether the ring of <paramref name="partition"/> is built and current: kept, so the refresh loop keeps it
    /// current, or opened within half a refresh period. A ring built and left out of the kept partitions since, as a
    /// tenant dropped and served again, has missed its refreshes.
    /// </summary>
    /// <remarks>
    /// Half a period, because a ring opened but not yet kept waits for the loop's next round once it is kept: opened
    /// within the window and kept at its end, it is refreshed again within one and a half periods, short of the
    /// propagation window a pod must not miss a new key for.
    /// </remarks>
    private bool IsCurrent(string partition, IReadOnlyCollection<string> kept)
    {
        if (!_rings.ContainsKey(partition))
            return false;

        if (kept.Contains(partition, StringComparer.Ordinal))
            return true;

        var period = serviceProvider.GetRequiredService<IOptions<KeyRingOptions>>().Value.RefreshPeriod;
        return _openedAt.TryGetValue(partition, out var openedAt) && Now - openedAt < period / 2;
    }

    private DateTimeOffset Now => serviceProvider.GetRequiredService<TimeProvider>().GetUtcNow();

    private async Task OpenAsync(string partition, KeyRingStoreRound round, CancellationToken cancellationToken)
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
        var ring = _rings.TryGetValue(partition, out var built) ? built : Build(partition);
        await ring.RefreshAsync(new PartitionedKeyRingStore(round, partition), cancellationToken);
        _rings.TryAdd(partition, ring);
        _openedAt[partition] = Now;
    }

    /// <summary>
    /// Refuses, before anything is served, what would leave a partition opened later unable to serve: keys adopted
    /// while the partitions come and go, which only the unnamed one may take, and a key-encryption key the custodian
    /// cannot show, which a ring keeping no partition yet would otherwise first meet on its first tenant.
    /// </summary>
    public async Task CheckAsync(CancellationToken cancellationToken)
    {
        // The settings' partitions are fixed at startup, so the ring meets each of them now; a host's own come later
        if (policy.AdoptedKeys.Count > 0 && partitionsKept is not OptionsKeyRingPartitions)
        {
            throw new InvalidOperationException(
                "Existing keys are adopted into a key ring whose partitions come and go while it runs, and adopted " +
                "keys go only into the unnamed partition of a ring serving one issuer. Mint new keys instead.");
        }

        var custodian = serviceProvider.GetRequiredService<IKeyCustodian>();
        if (await custodian.GetKeyVersionsAsync(policy.KeyEncryptionKeyName, cancellationToken)
                .AnyAsync(cancellationToken))
        {
            return;
        }

        throw new InvalidOperationException(
            $"The custodian holds no version of the key-encryption key '{policy.KeyEncryptionKeyName}', so the key " +
            "ring could open no key it mints.");
    }

    /// <summary>
    /// Starts a refresh round: the ring of every partition kept, each with its view of one read of the store taken
    /// for this round alone.
    /// </summary>
    /// <param name="exceptOpened">Leaves out the partitions refreshed when they were opened, as the round the
    /// ring starts with does.</param>
    public IReadOnlyList<(string Partition, KeyRing Ring, IKeyRingStore Source)> BeginRound(bool exceptOpened = false)
    {
        var round = new KeyRingStoreRound(store);
        return partitionsKept.Kept
            .Where(partition => !exceptOpened || !_openedAt.ContainsKey(partition))
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
    /// <remarks>
    /// The refusal counts the partitions kept rather than naming them: under multi-tenancy they name every tenant.
    /// </remarks>
    private string Kept(string partition)
    {
        var kept = partitionsKept.Kept;
        if (kept.Contains(partition, StringComparer.Ordinal))
            return partition;

        // The unnamed ring is what code written for a ring of one partition asks for
        throw new InvalidOperationException(partition == KeyRingOptions.DefaultPartition
            ? $"The key ring keeps {kept.Count} named partitions and no unnamed one, so there is no single " +
              $"{nameof(IKeyRing)} to serve: take the ring of one of its partitions from " +
              $"{nameof(IKeyRings)}.{nameof(IKeyRings.For)}."
            : $"The key ring keeps no partition '{partition}' among the {kept.Count} it keeps.");
    }

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
