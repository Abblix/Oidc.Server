// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The ring of each partition, built once over its view of the shared store (Registry): everyone asking for a
/// partition gets the same ring, the refresh loop that keeps it current included.
/// </summary>
/// <param name="factory">Builds each ring.</param>
/// <param name="setup">The partitions to keep.</param>
internal sealed class KeyRingRegistry(KeyRingFactory factory, KeyRingSetup setup)
{
    private readonly ConcurrentDictionary<string, KeyRing> _rings = new(StringComparer.Ordinal);

    // When each partition was last refreshed by an opening: the refresh loop's first round need not refresh such a
    // partition again, and an opening soon after finds it current
    private readonly ConcurrentDictionary<string, DateTimeOffset> _openedAt = new(StringComparer.Ordinal);

    /// <summary>
    /// The ring of <paramref name="partition"/>, built on first use.
    /// </summary>
    /// <remarks>
    /// A ring already built is served whether or not its partition is still kept: a request that began while its
    /// issuer was served finishes with that issuer's keys rather than failing for want of them.
    /// </remarks>
    public KeyRing Ring(string partition)
        => _rings.TryGetValue(partition, out var built) ? built : _rings.GetOrAdd(Kept(partition), factory.Build);

    /// <summary>
    /// The ring of <paramref name="partition"/> when it is built, and a new one, not kept yet, otherwise.
    /// </summary>
    public KeyRing Built(string partition)
        => _rings.TryGetValue(partition, out var built) ? built : factory.Build(partition);

    /// <summary>
    /// Keeps <paramref name="ring"/> as the ring of <paramref name="partition"/>, refreshed by an opening at
    /// <paramref name="openedAt"/>.
    /// </summary>
    public void Keep(string partition, KeyRing ring, DateTimeOffset openedAt)
    {
        _rings.TryAdd(partition, ring);
        _openedAt[partition] = openedAt;
    }

    /// <summary>
    /// Whether the ring of <paramref name="partition"/> is built and current: among <paramref name="kept"/>, so the
    /// refresh loop keeps it current, or opened less than <paramref name="window"/> before <paramref name="now"/>. A
    /// ring built and left out of the kept partitions since, as a tenant dropped and served again, has missed its
    /// refreshes.
    /// </summary>
    public bool IsCurrent(string partition, IReadOnlyCollection<string> kept, TimeSpan window, DateTimeOffset now)
    {
        if (!_rings.ContainsKey(partition))
            return false;

        if (kept.Contains(partition, StringComparer.Ordinal))
            return true;

        return _openedAt.TryGetValue(partition, out var openedAt) && now - openedAt < window;
    }

    /// <summary>
    /// Whether <paramref name="partition"/> was refreshed by an opening since its ring was built.
    /// </summary>
    public bool WasOpened(string partition) => _openedAt.ContainsKey(partition);

    /// <summary>
    /// Lets the ring of <paramref name="partition"/> go, its keys with it.
    /// </summary>
    public void Close(string partition)
    {
        _rings.TryRemove(partition, out _);
        _openedAt.TryRemove(partition, out _);
    }

    /// <summary>
    /// <paramref name="partition"/>, when the ring keeps it.
    /// </summary>
    /// <remarks>
    /// The refusal counts the partitions kept rather than naming them: under multi-tenancy they name every tenant.
    /// </remarks>
    private string Kept(string partition)
    {
        var kept = setup.PartitionsKept.Kept;
        if (kept.Contains(partition, StringComparer.Ordinal))
            return partition;

        // The unnamed ring is what code written for a ring of one partition asks for
        throw new InvalidOperationException(partition == KeyRingOptions.DefaultPartition
            ? $"The key ring keeps {kept.Count} named partitions and no unnamed one, so there is no single " +
              $"{nameof(IKeyRing)} to serve: take the ring of one of its partitions from " +
              $"{nameof(IKeyRings)}.{nameof(IKeyRings.For)}."
            : $"The key ring keeps no partition '{partition}' among the {kept.Count} it keeps.");
    }
}
