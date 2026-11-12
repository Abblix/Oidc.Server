// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;

namespace Abblix.Utils;

/// <summary>
/// Runs at most one load per key at a time, hands every caller asking meanwhile the same task, and keeps serving the
/// finished task, whether it succeeded or failed, for a hold time after it completes.
/// </summary>
/// <remarks>
/// <para>
/// Meant for documents read from somebody else's server when the number of reads is decided by whoever sends
/// requests here. Without it, every request arriving while a read is in flight starts a read of its own, and a server
/// that is failing is asked again by every request until it recovers, so its load grows exactly while it is down.
/// </para>
/// <para>
/// The hold is counted from the moment the load completes, so a slow load does not use it up. An entry leaves the
/// map when its hold ends, so keys that a caller chose and never asks for again do not accumulate. The hold of an
/// entry is the one passed by the caller that started its load.
/// </para>
/// <para>
/// The load runs under no caller's cancellation: it is shared, so one caller giving up must not fail the others.
/// Each caller's own token ends only that caller's wait.
/// </para>
/// </remarks>
/// <typeparam name="TKey">What identifies one load, such as the address of the document.</typeparam>
/// <typeparam name="TValue">What a load produces.</typeparam>
/// <param name="clock">Counts the hold.</param>
/// <param name="comparer">Decides which keys are the same load; the default equality when omitted.</param>
public sealed class CoalescingLoader<TKey, TValue>(TimeProvider clock, IEqualityComparer<TKey>? comparer = null)
    where TKey : notnull
{
    private sealed class Entry
    {
        public Lazy<Task<TValue>> Load { get; set; } = null!;

        // Referenced from the entry so the pending timer stays alive as long as the entry is in the map
        public ITimer? Release { get; set; }
    }

    private readonly ConcurrentDictionary<TKey, Entry> _entries = new(comparer);

    /// <summary>
    /// Returns the load in flight or held for <paramref name="key"/>, or starts <paramref name="load"/> when there
    /// is none.
    /// </summary>
    /// <param name="key">Identifies the load.</param>
    /// <param name="load">Produces the value; called at most once per entry.</param>
    /// <param name="hold">How long the finished task keeps being served; zero or less serves it only to the callers
    /// that arrived while it ran.</param>
    /// <param name="cancellationToken">Ends this caller's wait, not the load.</param>
    public Task<TValue> LoadAsync(
        TKey key,
        Func<TKey, Task<TValue>> load,
        TimeSpan hold,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(load);

        var entry = _entries.GetOrAdd(key, added => CreateEntry(added, load, hold));
        return entry.Load.Value.WaitAsync(cancellationToken);
    }

    private Entry CreateEntry(TKey key, Func<TKey, Task<TValue>> load, TimeSpan hold)
    {
        // GetOrAdd may build an entry it then discards; the load starts only when the stored one is first asked for
        var entry = new Entry();
        entry.Load = new Lazy<Task<TValue>>(() => RunAsync(key, entry, load, hold));
        return entry;
    }

    private async Task<TValue> RunAsync(TKey key, Entry entry, Func<TKey, Task<TValue>> load, TimeSpan hold)
    {
        try
        {
            return await load(key);
        }
        finally
        {
            Release(key, entry, hold);
        }
    }

    private void Release(TKey key, Entry entry, TimeSpan hold)
    {
        if (hold <= TimeSpan.Zero)
        {
            Remove(key, entry);
            return;
        }

        entry.Release = clock.CreateTimer(
            _ =>
            {
                Remove(key, entry);
                entry.Release?.Dispose();
            },
            state: null,
            dueTime: hold,
            period: Timeout.InfiniteTimeSpan);
    }

    // Removes this entry only: a later load for the same key has its own and keeps it
    private void Remove(TKey key, Entry entry)
        => _entries.TryRemove(new KeyValuePair<TKey, Entry>(key, entry));
}
