// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Runtime.CompilerServices;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Pins what the loader promises a server that somebody else's requests make it read from: one read for every caller
/// arriving together, no new read within the hold after one finished, succeeded or failed, and a new read once the
/// hold has passed. The number of loads started is the assertion each test is judged by.
/// </summary>
public class CoalescingLoaderTests
{
    private const string Key = "https://issuer.example.com/jwks";

    private static readonly TimeSpan Hold = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Callers arriving while a load runs wait for that load instead of starting their own, and all of them get
    /// what it produced. No hold is given, so only the sharing of the load in flight can keep the count at one.
    /// </summary>
    [Fact]
    public async Task CallersArrivingTogether_ShareOneLoad()
    {
        var loader = new CoalescingLoader<string, string>(new FakeTimeProvider());
        var pending = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var loads = 0;
        Task<string> Load(string _)
        {
            loads++;
            return pending.Task;
        }

        // Every caller has asked before the load completes
        var callers = Enumerable.Range(0, 32)
            .Select(_ => loader.LoadAsync(Key, Load, TimeSpan.Zero, TestContext.Current.CancellationToken))
            .ToArray();
        pending.SetResult("key-set");

        Assert.All(await Task.WhenAll(callers), value => Assert.Equal("key-set", value));
        Assert.Equal(1, loads);
    }

    /// <summary>
    /// A hold longer than any timer allows is served rather than refused, so a host turning the hold up to its
    /// maximum to mean "never again" gets exactly that.
    /// </summary>
    [Fact]
    public async Task AHoldOfTheLongestTimeSpan_IsServed()
    {
        var loader = new CoalescingLoader<string, string>(TimeProvider.System);
        var loads = 0;
        Task<string> Load(string _) => Task.FromResult($"key-set-{++loads}");

        Assert.Equal("key-set-1", await loader.LoadAsync(Key, Load, TimeSpan.MaxValue, TestContext.Current.CancellationToken));
        Assert.Equal("key-set-1", await loader.LoadAsync(Key, Load, TimeSpan.MaxValue, TestContext.Current.CancellationToken));
        Assert.Equal(1, loads);
    }

    /// <summary>
    /// A load that fails after every caller stopped waiting leaves no exception unobserved, which a host logging
    /// unobserved task exceptions would otherwise report for every such failure.
    /// </summary>
    [Fact]
    public async Task AFailureNobodyWaitsFor_IsNotReportedAsUnobserved()
    {
        // Only this test's failure is counted: other tests running meanwhile may leave exceptions of their own
        var probe = $"unreachable {Guid.NewGuid():N}";
        var unobserved = 0;
        void Count(object? sender, UnobservedTaskExceptionEventArgs args)
        {
            if (args.Exception.InnerExceptions.Any(exception => exception.Message == probe))
                Interlocked.Increment(ref unobserved);
        }

        TaskScheduler.UnobservedTaskException += Count;
        try
        {
            var pending = await StartAndAbandonALoadAsync();
            pending.SetException(new HttpRequestException(probe));

            // An unobserved exception is reported only when its task is finalized, on the finalizer's own thread, so
            // collecting, and giving the finalizer time, is the subject here
            for (var round = 0; round < 5; round++)
            {
#pragma warning disable S1215
                GC.Collect();
                GC.WaitForPendingFinalizers();
#pragma warning restore S1215
                await Task.Delay(TimeSpan.FromMilliseconds(50), TestContext.Current.CancellationToken);
            }
            Assert.Equal(0, Volatile.Read(ref unobserved));
        }
        finally
        {
            TaskScheduler.UnobservedTaskException -= Count;
        }
    }

    /// <summary>
    /// Starts a load whose only caller gives up, and returns what completes it. The loader is not returned, so once
    /// the load has failed nothing but the finalizer can reach its task.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<TaskCompletionSource<string>> StartAndAbandonALoadAsync()
    {
        var loader = new CoalescingLoader<string, string>(new FakeTimeProvider());

        // Continuations run inside SetException, so the load has failed by the time the caller collects
        var pending = new TaskCompletionSource<string>();
        using var givingUp = new CancellationTokenSource();

        var waiting = loader.LoadAsync(Key, _ => pending.Task, TimeSpan.Zero, givingUp.Token);
        await givingUp.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        return pending;
    }

    /// <summary>
    /// A failed load is served to the callers after it for the hold, so a server that is down is not asked again by
    /// every request; once the hold has passed, the next caller loads again.
    /// </summary>
    [Fact]
    public async Task AFailedLoad_IsServedForTheHold_AndLoadedAgainAfterIt()
    {
        var time = new FakeTimeProvider();
        var loader = new CoalescingLoader<string, string>(time);
        var loads = 0;
        Task<string> Failing(string _)
        {
            loads++;
            return Task.FromException<string>(new HttpRequestException("unreachable"));
        }

        await Assert.ThrowsAsync<HttpRequestException>(() => loader.LoadAsync(Key, Failing, Hold, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<HttpRequestException>(() => loader.LoadAsync(Key, Failing, Hold, TestContext.Current.CancellationToken));
        Assert.Equal(1, loads);

        time.Advance(Hold);
        await Assert.ThrowsAsync<HttpRequestException>(() => loader.LoadAsync(Key, Failing, Hold, TestContext.Current.CancellationToken));
        Assert.Equal(2, loads);
    }

    /// <summary>
    /// A successful load is served for the hold and not after it, so a caller asking once the hold has passed reads
    /// the document as it is then.
    /// </summary>
    [Fact]
    public async Task ASuccessfulLoad_IsServedForTheHold_AndLoadedAgainAfterIt()
    {
        var time = new FakeTimeProvider();
        var loader = new CoalescingLoader<string, string>(time);
        var loads = 0;
        Task<string> Load(string _) => Task.FromResult($"key-set-{++loads}");

        Assert.Equal("key-set-1", await loader.LoadAsync(Key, Load, Hold, TestContext.Current.CancellationToken));
        time.Advance(Hold - TimeSpan.FromSeconds(1));
        Assert.Equal("key-set-1", await loader.LoadAsync(Key, Load, Hold, TestContext.Current.CancellationToken));

        time.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal("key-set-2", await loader.LoadAsync(Key, Load, Hold, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The hold starts when the load completes, so a load slower than the hold is still served to the caller right
    /// after it.
    /// </summary>
    [Fact]
    public async Task TheHold_StartsWhenTheLoadCompletes()
    {
        var time = new FakeTimeProvider();
        var loader = new CoalescingLoader<string, string>(time);
        var pending = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var loads = 0;
        Task<string> Load(string _)
        {
            loads++;
            return pending.Task;
        }

        var first = loader.LoadAsync(Key, Load, Hold, TestContext.Current.CancellationToken);
        time.Advance(Hold + Hold);
        pending.SetResult("key-set");
        await first;

        Assert.Equal("key-set", await loader.LoadAsync(Key, Load, Hold, TestContext.Current.CancellationToken));
        Assert.Equal(1, loads);
    }

    /// <summary>
    /// With no hold, callers arriving while a load runs still share it, and the next caller after it loads again.
    /// </summary>
    [Fact]
    public async Task NoHold_SharesTheLoadInFlight_AndHoldsNothingAfterIt()
    {
        var loader = new CoalescingLoader<string, string>(new FakeTimeProvider());
        var pending = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var loads = 0;
        Task<string> Load(string _)
        {
            loads++;
            return loads == 1 ? pending.Task : Task.FromResult("key-set");
        }

        var first = loader.LoadAsync(Key, Load, TimeSpan.Zero, TestContext.Current.CancellationToken);
        var second = loader.LoadAsync(Key, Load, TimeSpan.Zero, TestContext.Current.CancellationToken);
        pending.SetResult("key-set");
        await Task.WhenAll(first, second);
        Assert.Equal(1, loads);

        await loader.LoadAsync(Key, Load, TimeSpan.Zero, TestContext.Current.CancellationToken);
        Assert.Equal(2, loads);
    }

    /// <summary>
    /// A caller giving up ends its own wait only: the load goes on for the others, and is not started again for them.
    /// </summary>
    [Fact]
    public async Task ACallerCancelling_DoesNotCancelTheLoadForTheOthers()
    {
        var loader = new CoalescingLoader<string, string>(new FakeTimeProvider());
        var pending = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var loads = 0;
        Task<string> Load(string _)
        {
            loads++;
            return pending.Task;
        }
        using var givingUp = new CancellationTokenSource();

        var cancelled = loader.LoadAsync(Key, Load, Hold, givingUp.Token);
        var waiting = loader.LoadAsync(Key, Load, Hold, TestContext.Current.CancellationToken);
        await givingUp.CancelAsync();
        pending.SetResult("key-set");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        Assert.Equal("key-set", await waiting);
        Assert.Equal(1, loads);
    }

    /// <summary>
    /// A stream of keys nobody asks for twice does not pile up: once their hold has passed, the entries are swept as
    /// later keys arrive, so the map holds about the keys still within their hold rather than every key ever seen.
    /// </summary>
    [Fact]
    public async Task KeysPastTheirHold_AreSweptAsNewKeysArrive()
    {
        const int keysPerWave = 1000;
        var time = new FakeTimeProvider();
        var loader = new CoalescingLoader<string, string>(time);

        for (var index = 0; index < keysPerWave; index++)
            await loader.LoadAsync($"first-{index}", Task.FromResult, Hold, TestContext.Current.CancellationToken);
        time.Advance(Hold);
        for (var index = 0; index < keysPerWave; index++)
            await loader.LoadAsync($"second-{index}", Task.FromResult, Hold, TestContext.Current.CancellationToken);

        Assert.InRange(loader.Count, keysPerWave, keysPerWave + keysPerWave / 2);
    }

    /// <summary>
    /// Loads of different keys do not wait for or serve each other.
    /// </summary>
    [Fact]
    public async Task DifferentKeys_LoadSeparately()
    {
        var loader = new CoalescingLoader<string, string>(new FakeTimeProvider());

        var first = await loader.LoadAsync("https://a.example.com/jwks", key => Task.FromResult(key), Hold, TestContext.Current.CancellationToken);
        var second = await loader.LoadAsync("https://b.example.com/jwks", key => Task.FromResult(key), Hold, TestContext.Current.CancellationToken);

        Assert.Equal("https://a.example.com/jwks", first);
        Assert.Equal("https://b.example.com/jwks", second);
    }
}
