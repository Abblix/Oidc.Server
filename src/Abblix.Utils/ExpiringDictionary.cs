// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;

namespace Abblix.Utils;

/// <summary>
/// A thread-safe dictionary whose entries expire a given time after they were added or last renewed, and whose
/// expired entries are removed as later ones are added.
/// </summary>
/// <remarks>
/// <para>
/// Lifetimes are counted on the monotonic clock of the <see cref="TimeProvider"/>, so a correction of the wall clock
/// neither shortens nor stretches them. An expired entry is invisible at once: it is not returned, and adding under
/// its key replaces it.
/// </para>
/// <para>
/// Expired entries are swept once as many entries have been added as the previous sweep kept, so a sweep costs,
/// spread over the additions it follows, a constant amount per addition however many distinct keys arrive, and the
/// dictionary holds at most about twice the entries that are still alive. Keys a caller chose and never uses again
/// therefore do not accumulate.
/// </para>
/// </remarks>
/// <typeparam name="TKey">The key.</typeparam>
/// <typeparam name="TValue">The value held under it.</typeparam>
/// <param name="clock">Counts the lifetimes.</param>
/// <param name="comparer">Decides which keys are the same; the default equality when omitted.</param>
public sealed class ExpiringDictionary<TKey, TValue>(TimeProvider clock, IEqualityComparer<TKey>? comparer = null)
    where TKey : notnull
{
    // Immutable, so a reader never sees a value with another entry's lifetime, and compared by reference, so replacing
    // or removing one entry never touches another that happens to hold equal fields
    private sealed class Entry(TValue value, long since, TimeSpan lifetime)
    {
        public TValue Value { get; } = value;

        public long Since { get; } = since;

        public TimeSpan Lifetime { get; } = lifetime;
    }

    // The fewest additions between two sweeps, so a dictionary holding few entries is not swept on every addition
    private const int MinimumAdditionsBetweenSweeps = 64;

    private readonly ConcurrentDictionary<TKey, Entry> _entries = new(comparer);
    private int _additionsSinceSweep;
    private int _additionsBeforeSweep = MinimumAdditionsBetweenSweeps;

    /// <summary>
    /// The entries held, expired ones included until the next sweep.
    /// </summary>
    internal int Count => _entries.Count;

    /// <summary>
    /// Returns the value under <paramref name="key"/> when it has not expired.
    /// </summary>
    public bool TryGetValue(TKey key, out TValue value)
    {
        if (_entries.TryGetValue(key, out var entry) && IsAlive(entry))
        {
            value = entry.Value;
            return true;
        }

        value = default!;
        return false;
    }

    /// <summary>
    /// Adds <paramref name="value"/> under <paramref name="key"/> unless a value that has not expired is already
    /// there; an expired one is replaced.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="value">The value to add.</param>
    /// <param name="lifetime">How long the value lives from now: <see cref="Timeout.InfiniteTimeSpan"/> for no
    /// expiry, and zero or any other negative value for an entry that has expired already.</param>
    /// <returns>Whether the value was added.</returns>
    public bool TryAdd(TKey key, TValue value, TimeSpan lifetime)
    {
        var added = new Entry(value, clock.GetTimestamp(), lifetime);
        while (true)
        {
            if (_entries.TryGetValue(key, out var held))
            {
                if (IsAlive(held))
                    return false;

                // Replaces the expired entry only: an entry another caller stored first is alive and wins
                if (_entries.TryUpdate(key, added, held))
                    return true;
            }
            else if (_entries.TryAdd(key, added))
            {
                SweepWhenDue();
                return true;
            }
        }
    }

    /// <summary>
    /// Starts the lifetime of the value under <paramref name="key"/> again from now, with
    /// <paramref name="lifetime"/>, provided the value held there is still <paramref name="value"/>.
    /// </summary>
    /// <returns>Whether the value was found and renewed; false when the key holds another value or none.</returns>
    public bool TryRenew(TKey key, TValue value, TimeSpan lifetime)
    {
        while (_entries.TryGetValue(key, out var held) && EqualityComparer<TValue>.Default.Equals(held.Value, value))
        {
            if (_entries.TryUpdate(key, new Entry(held.Value, clock.GetTimestamp(), lifetime), held))
                return true;
        }

        return false;
    }

    private bool IsAlive(Entry entry)
        => entry.Lifetime == Timeout.InfiniteTimeSpan || clock.GetElapsedTime(entry.Since) < entry.Lifetime;

    private void SweepWhenDue()
    {
        if (Interlocked.Increment(ref _additionsSinceSweep) < Volatile.Read(ref _additionsBeforeSweep))
            return;

        Interlocked.Exchange(ref _additionsSinceSweep, 0);
        var kept = 0;
        foreach (var (key, entry) in _entries)
        {
            if (IsAlive(entry))
                kept++;
            else
                _entries.TryRemove(new KeyValuePair<TKey, Entry>(key, entry));
        }

        Volatile.Write(ref _additionsBeforeSweep, Math.Max(MinimumAdditionsBetweenSweeps, kept));
    }
}
