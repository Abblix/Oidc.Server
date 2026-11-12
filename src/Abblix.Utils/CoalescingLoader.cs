// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
/// The loads are held in an <see cref="ExpiringDictionary{TKey,TValue}"/>: a load in flight does not expire, and a
/// finished one lives for the hold from the moment it completed, so a slow load does not use the hold up. The hold of
/// a load is the one passed by the caller that started it.
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
    private readonly ExpiringDictionary<TKey, Lazy<Task<TValue>>> _loads = new(clock, comparer);

    /// <summary>
    /// Returns the load in flight or held for <paramref name="key"/>, or starts <paramref name="load"/> when there
    /// is none.
    /// </summary>
    /// <param name="key">Identifies the load.</param>
    /// <param name="load">Produces the value; called at most once per load held.</param>
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
            if (_loads.TryGetValue(key, out var held))
                return held.Value.WaitAsync(cancellationToken);

            // A load that loses the race to be stored is dropped before it is ever started
            Lazy<Task<TValue>> started = null!;
            started = new Lazy<Task<TValue>>(() => Observed(RunAsync(key, started, load, hold)));
            if (_loads.TryAdd(key, started, Timeout.InfiniteTimeSpan))
                return started.Value.WaitAsync(cancellationToken);
        }
    }

    private async Task<TValue> RunAsync(TKey key, Lazy<Task<TValue>> started, Func<TKey, Task<TValue>> load, TimeSpan hold)
    {
        try
        {
            return await load(key);
        }
        finally
        {
            // Every hold that is not positive means the same, the infinite one among them, which is a negative value
            _loads.TryRenew(key, started, hold > TimeSpan.Zero ? hold : TimeSpan.Zero);
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
}
