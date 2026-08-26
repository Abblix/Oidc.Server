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
	private const string Key = "the-authorization";

	private static IDistributedCache CreateCache()
		=> new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

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
		Assert.True(await first);

		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();
		Assert.False(await second);
	}

	/// <summary>
	/// The outcome: a value that is gone was taken by somebody. This is the property issue 433 states, and
	/// on a single node it now holds.
	/// </summary>
	[Fact]
	public async Task TryRemoveAsync_ManyCallersOnOneKey_ExactlyOneTakesTheValue()
	{
		var cache = CreateCache();
		await cache.SetAsync(Key, Encoding.UTF8.GetBytes("value"), TestContext.Current.CancellationToken);

		var callers = Enumerable
			.Range(0, 8)
			.Select(_ => Task.Run(
				() => cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken),
				TestContext.Current.CancellationToken))
			.ToArray();

		var results = await Task.WhenAll(callers);

		Assert.Null(await cache.GetAsync(Key, TestContext.Current.CancellationToken));

		var winners = results.Count(won => won);
		Assert.True(winners == 1, $"the value was removed and {winners} callers were told they took it");
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

		Assert.True(await a);
		Assert.True(await b);
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
		await Assert.ThrowsAsync<InvalidOperationException>(() => failing);

		// The queued caller must get in. Bounded, because without the release it would wait forever and a
		// hanging test says nothing.
		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();

		var finished = await Task.WhenAny(
			queued, Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken));

		Assert.True(ReferenceEquals(finished, queued), "the lock was not released after the failure");
		Assert.True(await queued);
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
		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);

		cache.ResumeNext();
		Assert.True(await holder);

		// If the cancelled waiter had over-released, two callers could now be inside at once. Drive the
		// same arrangement again and require it to still serialize.
		await inner.SetAsync(Key, Encoding.UTF8.GetBytes("again"), TestContext.Current.CancellationToken);

		var a = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		await cache.WaitUntilParkedAsync(1);
		var b = cache.TryRemoveAsync(Key, cancellationToken: TestContext.Current.CancellationToken);
		for (var i = 0; i < 50; i++) await Task.Yield();

		Assert.Equal(1, cache.Parked);

		cache.ResumeNext();
		Assert.True(await a);
		await cache.WaitUntilParkedAsync(1);
		cache.ResumeNext();
		Assert.False(await b);
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
