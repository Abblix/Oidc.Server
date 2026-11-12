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
/// The hold is counted from the moment the load completes, so a slow load does not use it up, and the hold of an
/// entry is the one passed by the caller that started its load. An entry past its hold is no longer served, and it is
/// removed when a later load is added, so keys a caller chose and never asks for again do not accumulate.
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
        // Ticks of the instant the entry stops being served; the largest value while its load still runs
        private long _servedUntil = long.MaxValue;

        public Lazy<Task<TValue>> Load { get; set; } = null!;

        public void Complete(DateTimeOffset servedUntil) => Volatile.Write(ref _servedUntil, servedUntil.UtcTicks);

        public bool IsServedAt(DateTimeOffset now) => now.UtcTicks < Volatile.Read(ref _servedUntil);
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

        while (true)
        {
            var now = clock.GetUtcNow();
            if (_entries.TryGetValue(key, out var held))
            {
                if (held.IsServedAt(now))
                    return held.Load.Value.WaitAsync(cancellationToken);

                // Replaces this entry only: a caller that replaced it first has started the next load, which is served
                var next = CreateEntry(key, load, hold);
                if (_entries.TryUpdate(key, next, held))
                    return next.Load.Value.WaitAsync(cancellationToken);
            }
            else
            {
                var added = CreateEntry(key, load, hold);
                if (_entries.TryAdd(key, added))
                {
                    RemoveExpired(now);
                    return added.Load.Value.WaitAsync(cancellationToken);
                }
            }
        }
    }

    private Entry CreateEntry(TKey key, Func<TKey, Task<TValue>> load, TimeSpan hold)
    {
        // An entry that loses the race to be stored is dropped before its load is ever asked for
        var entry = new Entry();
        entry.Load = new Lazy<Task<TValue>>(() => Observed(RunAsync(key, entry, load, hold)));
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
            // Compared before adding, so no hold, however long or negative, makes the instant overflow
            var now = clock.GetUtcNow();
            if (hold <= TimeSpan.Zero)
                entry.Complete(now);
            else
                entry.Complete(hold < DateTimeOffset.MaxValue - now ? now + hold : DateTimeOffset.MaxValue);
        }
    }

    // Every caller may have stopped waiting before a load fails, and an exception nobody reads is reported as
    // unobserved; the callers still waiting read it from the same task
    private static Task<TValue> Observed(Task<TValue> task)
    {
        task.ContinueWith(
            static faulted => _ = faulted.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        return task;
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (var (key, entry) in _entries)
        {
            if (!entry.IsServedAt(now))
                _entries.TryRemove(new KeyValuePair<TKey, Entry>(key, entry));
        }
    }
}
