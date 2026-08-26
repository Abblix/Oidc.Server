// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Covers the guarantee <see cref="DistributedCacheExtensions.TryRemoveAsync"/> gives within one process:
/// exactly one caller removes the value, and it is never removed with nobody told they took it.
/// </summary>
/// <remarks>
/// The interleaving that loses a value needs two callers inside the protocol at once - one removing the
/// value while the other has already overwritten the lock token. Serializing callers on the key makes that
/// arrangement unreachable here, so the tests below measure the serialization directly rather than trying
/// to observe the absence of an interleaving.
/// </remarks>
public class RedemptionSerializationTests
{
	/// <summary>
	/// A key of its own per test instance. The gate table is static and lives for the process, so tests
	/// sharing a key share a gate: one that fails while holding it leaves every later test on that key
	/// waiting forever, and a hung test is reported as a smaller suite with nothing failing.
	/// </summary>
	private readonly string _suffix = Guid.NewGuid().ToString("N");

	private string Key => $"the-authorization-{_suffix}";

	private static IDistributedCache CreateCache()
		=> new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

	/// <summary>
	/// Awaits a caller that must throw, with a bound. <c>Assert.ThrowsAsync</c> on its own waits forever
	/// when the caller never answers, and a hung test does not fail the suite - it stops the runner, which
	/// then prints no summary at all.
	/// </summary>
	private static async Task<TException> ThrewAsync<TException>(Task caller)
		where TException : Exception
	{
		var finished = await Task.WhenAny(
			caller, Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

		Assert.True(ReferenceEquals(finished, caller), "the caller never answered");
		return await Assert.ThrowsAnyAsync<TException>(() => caller);
	}

	/// <summary>
	/// Awaits a caller with a bound. A redemption that never answers must fail this suite rather than stop
	/// it: a hung test takes the rest of its class with it, and the run then reports fewer tests and no
	/// failures, which is indistinguishable from a pass.
	/// </summary>
	private static async Task<bool> AnsweredAsync(Task<bool> caller)
	{
		var finished = await Task.WhenAny(
			caller, Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

		Assert.True(ReferenceEquals(finished, caller), "the caller never answered");
		return await caller;
	}

	/// <summary>
	/// The control. Without it, a serialized second caller would be indistinguishable from a gate that
	/// never lets anybody through.
	/// </summary>
	[Fact]
	public async Task TryRemoveAsync_OneCaller_TakesTheValue()
	{
		var cache = CreateCache();
		await cache.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);

		Assert.True(await cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken));
		Assert.Null(await cache.GetAsync(Key, TestContext.Current.CancellationToken));
	}

	/// <summary>
	/// The mechanism: a second caller on the same key cannot enter the protocol while the first is inside
	/// it. This is what makes the losing interleaving unconstructible rather than merely unlikely.
	/// </summary>
	[Fact]
	public async Task TryRemoveAsync_SameKey_TheSecondCallerWaitsOutsideTheProtocol()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);
		var cache = new ParkOnValueRead(inner, Key);

		// The first caller enters and parks at its read of the value, holding the key.
		var first = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);

		// The second is started and given every chance to get in.
		var second = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		for (var i = 0; i < 50; i++) await Task.Yield();

		// It did not. One caller is inside the protocol, not two - which is the whole property.
		Assert.Equal(1, cache.Parked);

		cache.ResumeNext();
		Assert.True(await AnsweredAsync(first));

		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();
		Assert.False(await AnsweredAsync(second));
	}

	/// <summary>
	/// The outcome: a value that is gone was taken by somebody. This is the property issue 433 states, and
	/// where one process touches the key it now holds.
	/// </summary>
	/// <remarks>
	/// Driven rather than raced. Eight callers started at once measure the scheduler: the distributed
	/// protocol already picks at most one winner in almost every arrangement, so a run with a winner says
	/// nothing, and the arrangement with NO winner has to be built to be seen.
	///
	/// Here both callers are pointed at their read and then released one at a time. Serialized, the second
	/// cannot reach its read while the first is inside, so the first wins and the second finds nothing.
	/// Unserialized, both reach it, the first removes the value and reads back a lock token that is no
	/// longer its own, and the second finds nothing - and nobody won.
	/// </remarks>
	[Fact]
	public async Task TryRemoveAsync_TwoCallersOnOneKey_SomebodyIsToldTheyTookIt()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);
		var cache = new ParkOnValueRead(inner, Key);

		var first = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);

		var second = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);

		// Give the second every chance to get in beside the first. Under a gate it does not; without one it
		// does, and that is the arrangement in which the value is lost.
		for (var i = 0; i < 50; i++) await Task.Yield();

		// Release the first and let it FINISH before releasing the second. Resuming both and yielding
		// between them is not the same thing and does not build the arrangement: the second's read runs
		// before the first's removal, so it finds the value still there, removes it itself and comes away
		// holding the surviving token - one winner, by luck, in a build with no serialization at all.
		cache.ResumeNext();
		var firstWon = await AnsweredAsync(first);

		// Serialized, the second only reaches its read now; unserialized it has been parked since before
		// the first ran. Either way its gate is the next one out.
		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();
		var secondWon = await AnsweredAsync(second);

		Assert.Null(await inner.GetAsync(Key, TestContext.Current.CancellationToken));

		var winners = (firstWon ? 1 : 0) + (secondWon ? 1 : 0);
		Assert.True(winners == 1, $"the value was removed and {winners} callers were told they took it");
	}

	/// <summary>
	/// The table holds gates only while calls are in flight, which is what keeps it the size of the traffic
	/// rather than of every authorization the deployment ever issued.
	/// </summary>
	[Fact]
	public async Task TryRemoveAsync_AfterTheCallsFinish_NoGateIsLeftBehind()
	{
		var cache = CreateCache();

		foreach (var key in new[] { $"one-{_suffix}", $"two-{_suffix}", $"three-{_suffix}" })
		{
			await cache.SetAsync(key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);
			Assert.True(await cache.TryRemoveAsync(key, cancellationToken: TestContext.Current.CancellationToken));
		}

		Assert.Equal(0, LiveGatesForThisTest());
	}

	/// <summary>
	/// The table the locks live in. Asserting on it directly is the only way to see a leak: a table that
	/// never forgets behaves identically until the process runs out of memory.
	/// </summary>
	/// <remarks>
	/// Counted under its own lock, because other tests in this process redeem their own keys at the same
	/// time - only THIS test's keys are asserted about, and a bare Count would race them.
	/// </remarks>
	private int LiveGatesForThisTest()
	{
		lock (DistributedCacheExtensions.Gates)
		{
			return DistributedCacheExtensions.Gates.Keys.Count(key => key.Contains(_suffix, StringComparison.Ordinal));
		}
	}

	/// <summary>
	/// Different keys must not wait on each other, or the gate would serialize the whole endpoint rather
	/// than one redemption.
	/// </summary>
	[Fact]
	public async Task TryRemoveAsync_DifferentKeys_DoNotWaitOnEachOther()
	{
		var inner = CreateCache();
		await inner.SetAsync("first", Encoding.UTF8.GetBytes("a"), TestContext.Current.CancellationToken);
		await inner.SetAsync("second", Encoding.UTF8.GetBytes("b"), TestContext.Current.CancellationToken);
		var cache = new ParkOnValueRead(inner, "first", "second");

		var a = cache.TryRemoveAsync("first", cancellationToken: TestContext.Current.CancellationToken);
		var b = cache.TryRemoveAsync("second", cancellationToken: TestContext.Current.CancellationToken);

		// Both reach their read. Under a gate shared across keys the second would still be waiting.
		await cache.WaitUntilParkedAsync(2);

		cache.ResumeNext();
		cache.ResumeNext();

		Assert.True(await AnsweredAsync(a));
		Assert.True(await AnsweredAsync(b));
	}

	/// <summary>
	/// A failure inside the guarded section must still release the lock, with somebody already queued
	/// behind it - or that caller waits for a lock nobody will ever hand back.
	/// </summary>
	/// <remarks>
	/// The queue is what makes this measurable. A failure with nobody waiting is invisible: the entry's
	/// last share goes back, the entry is retired, and the next caller rents a fresh lock and walks
	/// straight in whether or not the failed one released anything. Only a caller already waiting on THAT
	/// lock can tell the difference.
	/// </remarks>
	[Fact]
	public async Task TryRemoveAsync_TheProtocolThrowsWithACallerQueued_TheLockIsStillReleased()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);
		var cache = new ParkThenThrowOnValueRead(inner, Key);

		// The first caller holds the lock and parks inside the guarded section.
		var failing = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);

		// The second queues on the same lock, so the entry cannot be retired out from under it.
		var queued = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		for (var i = 0; i < 50; i++) await Task.Yield();
		Assert.Equal(1, cache.Parked);

		// Resume the first, which now fails inside the section.
		cache.ResumeNext();
		await ThrewAsync<InvalidOperationException>(failing);

		// The queued caller must get in. Bounded, because without the release it would wait forever and a
		// hanging test says nothing.
		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();

		var finished = await Task.WhenAny(
			queued, Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

		Assert.True(ReferenceEquals(finished, queued), "the lock was not released after the failure");
		Assert.True(await AnsweredAsync(queued));
		Assert.Null(await inner.GetAsync(Key, TestContext.Current.CancellationToken));
	}

	/// <summary>
	/// Cancellation while WAITING for the lock is the other half: the caller never acquired it, so it must
	/// not release it, and it must still give back its share of the entry.
	/// </summary>
	/// <remarks>
	/// Releasing a semaphore that was never taken raises its count, which is worse than a wedge: the next
	/// two callers both get in and the interleaving this whole change exists to prevent forms again.
	/// </remarks>
	[Fact]
	public async Task TryRemoveAsync_CancelledWhileWaiting_LeavesTheLockUsable()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);
		var cache = new ParkOnValueRead(inner, Key);

		var holder = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);

		using var cancelled = new CancellationTokenSource();
		var waiter = cache.TryRemoveAsync(Key, cancellationToken: cancelled.Token);
		await cancelled.CancelAsync();
		await ThrewAsync<OperationCanceledException>(waiter);

		cache.ResumeNext();
		Assert.True(await AnsweredAsync(holder));

		// If the cancelled waiter had over-released, two callers could now be inside at once. Drive the
		// same arrangement again and require it to still serialize.
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("again"), TestContext.Current.CancellationToken);

		var a = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);
		var b = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		for (var i = 0; i < 50; i++) await Task.Yield();

		Assert.Equal(1, cache.Parked);

		cache.ResumeNext();
		Assert.True(await AnsweredAsync(a));
		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();
		Assert.False(await AnsweredAsync(b));
	}

	/// <summary>
	/// Parks every read of <paramref name="gatedKey"/>, and makes the FIRST of them throw when resumed, so
	/// the failure lands inside the guarded section with a caller already queued behind it.
	/// </summary>
	private sealed class ParkThenThrowOnValueRead(IDistributedCache inner, string gatedKey) : IDistributedCache
	{
		private readonly Queue<TaskCompletionSource> _parked = new();
		private readonly Lock _sync = new();
		private int _reads;

		public int Parked
		{
			get
			{
				lock (_sync) return _parked.Count;
			}
		}

		public async Task WaitUntilParkedAsync(int count)
		{
			for (var i = 0; i < 1000 && Parked < count; i++) await Task.Yield();
			Assert.Equal(count, Parked);
		}

		public void ResumeNext()
		{
			TaskCompletionSource gate;
			lock (_sync) gate = _parked.Dequeue();
			gate.SetResult();
		}

		public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
		{
			if (key != gatedKey)
				return await inner.GetAsync(key, token);

			var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
			lock (_sync) _parked.Enqueue(gate);
			await gate.Task;

			if (Interlocked.Increment(ref _reads) == 1)
				throw new InvalidOperationException("the store failed mid-redemption");

			return await inner.GetAsync(key, token);
		}

		public Task SetAsync(
			string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
			=> inner.SetAsync(key, value, options, token);

		public Task RemoveAsync(string key, CancellationToken token = default)
			=> inner.RemoveAsync(key, token);

		public Task RefreshAsync(string key, CancellationToken token = default)
			=> inner.RefreshAsync(key, token);

		public byte[]? Get(string key) => inner.Get(key);

		public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
			=> inner.Set(key, value, options);

		public void Remove(string key) => inner.Remove(key);

		public void Refresh(string key) => inner.Refresh(key);
	}

	/// <summary>
	/// Parks every read of one of <paramref name="gatedKeys"/> until the test resumes it. The lock keys the
	/// protocol reads are deliberately not among them: parking those would suspend a caller somewhere the
	/// property under test says nothing about.
	/// </summary>
	private sealed class ParkOnValueRead(IDistributedCache inner, params string[] gatedKeys) : IDistributedCache
	{
		private readonly HashSet<string> _gated = [..gatedKeys];

		private readonly Queue<TaskCompletionSource> _parked = new();
		private readonly Lock _sync = new();

		public int Parked
		{
			get
			{
				lock (_sync) return _parked.Count;
			}
		}

		public async Task WaitUntilParkedAsync(int count)
		{
			for (var i = 0; i < 1000 && Parked < count; i++) await Task.Yield();
			Assert.Equal(count, Parked);
		}

		public void ResumeNext()
		{
			TaskCompletionSource gate;
			lock (_sync) gate = _parked.Dequeue();
			gate.SetResult();
		}

		public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
		{
			if (_gated.Contains(key))
			{
				var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
				lock (_sync) _parked.Enqueue(gate);
				await gate.Task;
			}

			return await inner.GetAsync(key, token);
		}

		public Task SetAsync(
			string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
			=> inner.SetAsync(key, value, options, token);

		public Task RemoveAsync(string key, CancellationToken token = default)
			=> inner.RemoveAsync(key, token);

		public Task RefreshAsync(string key, CancellationToken token = default)
			=> inner.RefreshAsync(key, token);

		public byte[]? Get(string key) => inner.Get(key);

		public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
			=> inner.Set(key, value, options);

		public void Remove(string key) => inner.Remove(key);

		public void Refresh(string key) => inner.Refresh(key);
	}
}
