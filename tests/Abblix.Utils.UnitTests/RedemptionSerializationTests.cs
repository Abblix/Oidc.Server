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
/// Covers what <see cref="DistributedCacheExtensions.TryRemoveAsync"/> decides: a caller is told it took
/// the value only when its own lock token is still in the store at the end of the protocol.
/// </summary>
/// <remarks>
/// Serializing callers on a key stops one of them overwriting another's token, which is one of the three
/// ways a value goes with nobody told. The tests below measure that serialization directly rather than
/// trying to observe the absence of an interleaving - and then measure the ways it does NOT close, one
/// test each for an expiring claim and for a store fault after the removal, because a guarantee stated as
/// a list of prevented causes is the shape that keeps turning out to be short by one.
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

		// The second is started and given a real window of time to get in. It does not: one caller is
		// inside the protocol, not two, which is the whole property.
		var second = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		Assert.False(await cache.ParkedReachedAsync(2));

		cache.ResumeNext();
		Assert.True(await AnsweredAsync(first));

		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();
		Assert.False(await AnsweredAsync(second));
	}

	/// <summary>
	/// The outcome the serialization buys: with no competitor able to overwrite a token, a value that is
	/// gone was taken by somebody. Issue 433's property, for the one cause this closes.
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

		// Give the second a real window to get in beside the first. Under a gate it does not; without one
		// it does, and that is the arrangement in which the value is lost.
		Assert.False(await cache.ParkedReachedAsync(2));

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
	/// Serializing callers closes ONE of the three ways a redemption loses its value. This is a second one,
	/// and it needs neither a competitor nor a second node.
	/// </summary>
	/// <remarks>
	/// A caller reports a loss when the lock token it reads back is not the one it wrote. Somebody
	/// overwriting it needs a competitor; the lock EXPIRING needs only time, and three cache round trips
	/// sit between writing it and reading it back. So a stalled call, a collection pause or a starved
	/// thread pool is enough - which is why the remarks say so rather than blaming a second node.
	///
	/// Driven with a delay rather than waited out: the point is the ordering, not the duration.
	/// </remarks>
	[Fact]
	public async Task TryRemoveAsync_TheLockExpiresMidProtocol_OneCallerAloneLosesTheValue()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);

		var cache = new SlowValueRead(inner, Key, TimeSpan.FromMilliseconds(200));

		var won = await cache.TryRemoveAsync(
			Key,
			lockTimeout: TimeSpan.FromMilliseconds(50),
			cancellationToken: TestContext.Current.CancellationToken);

		// Both halves, because either one alone reads as something else: a false with the value still
		// there is an ordinary refusal, and a missing value with a true is a normal redemption.
		Assert.False(won);
		Assert.Null(await inner.GetAsync(Key, TestContext.Current.CancellationToken));
	}

	/// <summary>
	/// The control for the test above. With the lock outliving the protocol, the same single caller wins,
	/// so what that test measures is the expiry and not the delay.
	/// </summary>
	[Fact]
	public async Task TryRemoveAsync_TheLockOutlivesTheProtocol_TheOneCallerWins()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);

		var cache = new SlowValueRead(inner, Key, TimeSpan.FromMilliseconds(200));

		var won = await cache.TryRemoveAsync(
			Key,
			lockTimeout: TimeSpan.FromSeconds(30),
			cancellationToken: TestContext.Current.CancellationToken);

		Assert.True(won);
		Assert.Null(await inner.GetAsync(Key, TestContext.Current.CancellationToken));
	}

	/// <summary>
	/// Passes everything through, delaying only the read of one key, which is how the protocol is made to
	/// outlast its own lock without the test waiting out a real timeout.
	/// </summary>
	private sealed class SlowValueRead(IDistributedCache inner, string slowKey, TimeSpan delay) : IDistributedCache
	{
		public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
		{
			if (key == slowKey) await Task.Delay(delay, token);
			return await inner.GetAsync(key, token);
		}

		public Task SetAsync(
			string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
			=> inner.SetAsync(key, value, options, token);

		public Task RemoveAsync(string key, CancellationToken token = default) => inner.RemoveAsync(key, token);

		public Task RefreshAsync(string key, CancellationToken token = default) => inner.RefreshAsync(key, token);

		public byte[]? Get(string key) => inner.Get(key);

		public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
			=> inner.Set(key, value, options);

		public void Remove(string key) => inner.Remove(key);

		public void Refresh(string key) => inner.Refresh(key);
	}

	/// <summary>
	/// The third way, and the one no amount of serialization or lock lifetime reaches: the removal
	/// succeeds and a store call AFTER it fails.
	/// </summary>
	/// <remarks>
	/// The protocol removes the value and then makes two more round trips to the same store - reading the
	/// lock token back and cleaning it up. A fault in either leaves the value gone and the caller holding
	/// an exception rather than an answer, so nothing anywhere reports a winner.
	///
	/// This is why the guarantee is stated as what must be TRUE for a win rather than as a list of ways to
	/// lose: the list was short by this one for four review rounds.
	/// </remarks>
	[Fact]
	public async Task TryRemoveAsync_TheStoreFaultsAfterTheRemoval_TheValueIsGoneAndNobodyIsTold()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);

		var cache = new FaultAfterValueRemoval(inner, Key);

		await Assert.ThrowsAsync<TimeoutException>(
			() => cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken));

		// The half that matters: the caller got no answer AND the value is gone. Either alone is ordinary -
		// a fault before the removal loses nothing, and a false over a present value is a plain refusal.
		Assert.Null(await inner.GetAsync(Key, TestContext.Current.CancellationToken));
	}

	/// <summary>
	/// Passes everything through until the value is removed, then faults the next read - which is the lock
	/// read-back, the first thing the protocol does once the value is already gone.
	/// </summary>
	private sealed class FaultAfterValueRemoval(IDistributedCache inner, string valueKey) : IDistributedCache
	{
		private bool _removed;

		public async Task RemoveAsync(string key, CancellationToken token = default)
		{
			await inner.RemoveAsync(key, token);
			if (key == valueKey) _removed = true;
		}

		public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
		{
			if (_removed) throw new TimeoutException("the store stopped answering after the removal");
			return await inner.GetAsync(key, token);
		}

		public Task SetAsync(
			string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
			=> inner.SetAsync(key, value, options, token);

		public Task RefreshAsync(string key, CancellationToken token = default) => inner.RefreshAsync(key, token);

		public byte[]? Get(string key) => inner.Get(key);

		public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
			=> inner.Set(key, value, options);

		public void Remove(string key) => inner.Remove(key);

		public void Refresh(string key) => inner.Refresh(key);
	}

	/// <summary>
	/// Different keys must not wait on each other, or the gate would serialize the whole endpoint rather
	/// than one redemption.
	/// </summary>
	[Fact]
	public async Task TryRemoveAsync_DifferentKeys_DoNotWaitOnEachOther()
	{
		var first = $"{Key}-first";
		var second = $"{Key}-second";

		var inner = CreateCache();
		await inner.SetAsync(first, Encoding.UTF8.GetBytes("a"), TestContext.Current.CancellationToken);
		await inner.SetAsync(second, Encoding.UTF8.GetBytes("b"), TestContext.Current.CancellationToken);
		var cache = new ParkOnValueRead(inner, first, second);

		var a = cache.TryRemoveAsync(first, cancellationToken: TestContext.Current.CancellationToken);
		var b = cache.TryRemoveAsync(second, cancellationToken: TestContext.Current.CancellationToken);

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
		var cache = new ParkOnValueRead(inner, Key)
		{
			AfterResume = resumed =>
			{
				if (resumed == 1) throw new InvalidOperationException("the store failed mid-redemption");
			},
		};

		// The first caller holds the lock and parks inside the guarded section.
		var failing = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);

		// The second queues on the same lock, so the entry cannot be retired out from under it.
		var queued = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		Assert.False(await cache.ParkedReachedAsync(2));

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
		Assert.False(await cache.ParkedReachedAsync(2));

		cache.ResumeNext();
		Assert.True(await AnsweredAsync(a));
		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();
		Assert.False(await AnsweredAsync(b));
	}

	/// <summary>
	/// The value read by <see cref="DistributedCacheExtensions.TryGetAndRemoveAsync"/> is read INSIDE the
	/// serialized section, not before waiting for it.
	/// </summary>
	/// <remarks>
	/// Measured by where the read happens rather than by trying to observe a stale value: one caller holds
	/// the gate, parked at its own protocol read, and a second calls the take-once. If its read is outside
	/// the gate it happens at once and parks too, so the store sees TWO parked reads; if it is inside, the
	/// second caller is still waiting and the store sees one.
	/// <para>
	/// What this buys is the width of the window rather than its closure. Before, the bytes handed back
	/// were the bytes present before an unbounded wait - the whole of another caller's redemption. Now they
	/// are the bytes present when this caller got in, and what remains open is the removal protocol's own
	/// few steps, to a writer that takes no gate and to any second process at all. That is issue 435, and
	/// it needs a store primitive this interface does not expose.
	/// </para>
	/// </remarks>
	[Fact]
	public async Task TryGetAndRemoveAsync_ReadsInsideTheSerializedSection()
	{
		var inner = CreateCache();
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);
		var cache = new ParkOnValueRead(inner, Key);

		// The holder parks at its protocol read, inside the gate.
		var holder = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);

		// One, not two: the taker has not read anything, because it is waiting for the gate the holder has.
		var taker = cache.TryGetAndRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		Assert.False(await cache.ParkedReachedAsync(2));

		cache.ResumeNext();
		Assert.True(await AnsweredAsync(holder));

		// And it does read, once it is in. One park rather than two: the holder took the value, so the read
		// finds nothing and the removal protocol - which would have read again - is never reached.
		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();

		var taken = await Task.WhenAny(
			taker, Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));
		Assert.True(ReferenceEquals(taken, taker), "the taker never answered");

		// The holder took the value, so there is nothing left for the taker: null is the right answer, and
		// the row is about WHERE it looked rather than what it found.
		Assert.Null(await taker);
	}

	/// <summary>
	/// Parks every read of one of <paramref name="gatedKeys"/> until the test resumes it. The lock keys the
	/// protocol reads are deliberately not among them: parking those would suspend a caller somewhere the
	/// property under test says nothing about.
	/// </summary>
	/// <remarks>
	/// One double rather than two. A second copy differing only in what happens after the read is resumed
	/// is a copy that drifts: a fix to the parking, the counting or the resume order lands in one of them.
	/// What varies is passed in.
	/// </remarks>
	private sealed class ParkOnValueRead(IDistributedCache inner, params string[] gatedKeys) : IDistributedCache
	{
		/// <summary>
		/// How long a wait for a parker may take before it is called a failure of the instrument rather
		/// than of the property. Generous, because it is never spent on a passing run - a passing run
		/// completes on the signal - and a busy shared runner is exactly where a tighter bound turns a
		/// green property red.
		/// </summary>
		private static readonly TimeSpan ParkTimeout = TimeSpan.FromSeconds(30);

		/// <summary>
		/// How long a caller that should be held OUT is given to prove otherwise. Short, because this one
		/// is spent on every passing run, and it is a fail-early assertion rather than the proof - see
		/// <see cref="ParkedReachedAsync"/>.
		/// </summary>
		private static readonly TimeSpan SettleWindow = TimeSpan.FromMilliseconds(250);

		private readonly HashSet<string> _gated = [..gatedKeys];
		private readonly Queue<TaskCompletionSource> _parked = new();
		private readonly List<(int Count, TaskCompletionSource Reached)> _watchers = [];
		private readonly Lock _sync = new();
		private int _resumedReads;

		/// <summary>
		/// Runs after a resumed read, before the value is fetched, so a test can make the store fail INSIDE
		/// the guarded section rather than before it. The argument is how many reads have been resumed so
		/// far, one-based, which is how a test says "only the first".
		/// </summary>
		public Action<int>? AfterResume { get; init; }

		/// <summary>
		/// Completes when at least <paramref name="count"/> callers are parked, and throws
		/// <see cref="TimeoutException"/> if that has not happened within <see cref="ParkTimeout"/>.
		/// </summary>
		/// <remarks>
		/// The wait is on a SIGNAL raised where the parking happens, not on a spin over
		/// the parked count. A spin bounded by iterations of <c>Task.Yield</c> is bounded by
		/// scheduling rather than by time: the yielding continuations go to the running thread's local
		/// queue, so the loop can run to exhaustion on a busy pool while the awaited party's continuation
		/// is still sitting in the global one. The two readings the test needs to tell apart - "the gate
		/// held it out" and "the pool has not run it yet" - are then the same reading, and the row fails
		/// in milliseconds under load having measured nothing.
		/// <para>
		/// The timeout is what keeps the instrument's own failure a DIFFERENT outcome from the property
		/// being false: a <see cref="TimeoutException"/> says the parker never arrived, where a failed
		/// assertion would say the gate admitted the wrong number.
		/// </para>
		/// </remarks>
		public Task WaitUntilParkedAsync(int count)
		{
			TaskCompletionSource reached;
			lock (_sync)
			{
				if (_parked.Count >= count) return Task.CompletedTask;

				reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
				_watchers.Add((count, reached));
			}

			return reached.Task.WaitAsync(ParkTimeout);
		}

		/// <summary>
		/// Whether <paramref name="count"/> callers park within <see cref="SettleWindow"/>. Used to assert
		/// that one does NOT: a caller held out by the gate never arrives, and the window is what makes
		/// that a statement about elapsed time rather than about how many continuations happened to run.
		/// </summary>
		/// <remarks>
		/// A negative bounded by a window can only ever say "not within this long", so it is not what
		/// carries these rows. The proof is the ADMISSION that follows: after the holder is resumed, the
		/// same caller parks, and it could not have done so twice. This assertion exists to fail early and
		/// legibly when the gate lets both in at once, where waiting for the admission would pass.
		/// </remarks>
		public async Task<bool> ParkedReachedAsync(int count)
		{
			try
			{
				await WaitUntilParkedAsync(count).WaitAsync(SettleWindow);
				return true;
			}
			catch (TimeoutException)
			{
				return false;
			}
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

				// Chosen under the same lock that enqueues, so a waiter registering concurrently either
				// sees the new count itself or is in this list, never neither. Completed outside it, to
				// keep what the lock covers to the state it guards.
				List<TaskCompletionSource> reached;
				lock (_sync)
				{
					_parked.Enqueue(gate);
					reached = [.._watchers.Where(w => w.Count <= _parked.Count).Select(w => w.Reached)];
					_watchers.RemoveAll(w => w.Count <= _parked.Count);
				}

				foreach (var watcher in reached) watcher.SetResult();

				await gate.Task;

				AfterResume?.Invoke(Interlocked.Increment(ref _resumedReads));
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
