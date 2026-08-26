// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.Utils;

/// <summary>
/// Extension methods for <see cref="IDistributedCache"/> providing atomic operations.
/// </summary>
public static class DistributedCacheExtensions
{
	/// <summary>
	/// Marker value stored by <see cref="TryAddAsync"/>: presence of the key is the fact, the
	/// stored bytes carry no information of their own.
	/// </summary>
	private static readonly byte[] PresenceMarker = [1];

	/// <summary>
	/// Floor applied to the time-to-live requested from <see cref="TryAddAsync"/>.
	/// <see cref="DistributedCacheEntryOptions.AbsoluteExpirationRelativeToNow"/> rejects a zero or
	/// negative value outright, and a caller-side clock skew can legitimately produce one; the floor
	/// keeps a skewed caller marking instead of throwing, at the cost of remembering a few seconds
	/// longer than asked.
	/// </summary>
	private static readonly TimeSpan MinimumTimeToLive = TimeSpan.FromSeconds(10);

	/// <summary>
	/// Marks a key as present unless it already is, telling a first call from a repeat: the
	/// add-if-absent primitive replay caches and other "seen before?" checks are built on.
	/// </summary>
	/// <remarks>
	/// <para>
	/// <strong>Not atomic:</strong> <see cref="IDistributedCache"/> exposes only Get + Set, no
	/// compare-and-set primitive, so two concurrent callers of the same key can both observe a miss
	/// before either writes and both hear "new". The race window is bounded by the cache round-trip,
	/// which makes the duplicate-detection guarantee probabilistic rather than strict. Callers whose
	/// domain needs strict exactly-once use a backend-aware primitive instead - for replay prevention
	/// that is a <c>ReplayCacheBase</c> over the store's own conditional write (Redis
	/// <c>SET ... NX PX</c>, SQL <c>INSERT ... ON CONFLICT DO NOTHING</c>).
	/// </para>
	/// <para>
	/// The entry stores an opaque marker; only the key's presence carries meaning. The requested
	/// time-to-live is floored to a small positive minimum so a value the cache would reject or
	/// discard immediately still records the sighting.
	/// </para>
	/// </remarks>
	/// <param name="cache">The distributed cache instance.</param>
	/// <param name="key">The key whose first sighting is being recorded.</param>
	/// <param name="timeToLive">How long the sighting is remembered.</param>
	/// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
	/// <returns>
	/// A task containing true when the key was absent and is now marked; false when it was
	/// already present.
	/// </returns>
	public static async Task<bool> TryAddAsync(
		this IDistributedCache cache,
		string key,
		TimeSpan timeToLive,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(cache);
		ArgumentNullException.ThrowIfNull(key);

		if (await cache.GetAsync(key, cancellationToken) != null)
		{
			return false;
		}

		if (timeToLive < MinimumTimeToLive)
		{
			timeToLive = MinimumTimeToLive;
		}

		await cache.SetAsync(
			key,
			PresenceMarker,
			new () { AbsoluteExpirationRelativeToNow = timeToLive },
			cancellationToken);

		return true;
	}

	/// <summary>
	/// Atomically retrieves and removes a value from the distributed cache.
	/// Uses a lock-based protocol to ensure atomic get-and-remove semantics even when the underlying
	/// cache implementation doesn't support native atomic operations (e.g., Redis GETDEL).
	/// </summary>
	/// <remarks>
	/// <para><strong>Atomicity Protocol:</strong></para>
	/// <list type="number">
	///   <item><term>Step 1:</term> Get the value from cache</item>
	///   <item><term>Step 2:</term> Delegate to <see cref="TryRemoveAsync"/> for atomic removal</item>
	/// </list>
	/// <para>
	/// <strong>How it provides atomicity:</strong> In a race between multiple threads, only the thread whose
	/// lock token survives (last-write-wins) will return the value. Other threads detect the lock mismatch
	/// and return null. So where one process touches the key, exactly one caller retrieves the value, even
	/// though the individual cache operations are not atomic - and across processes, at most one. The
	/// difference, and what to do about it, is under <see cref="TryRemoveAsync"/>, which this delegates to
	/// and which carries the guarantee.
	/// </para>
	/// <para>
	/// <strong>Lock timeout:</strong> Locks auto-expire after the specified timeout (default 5 seconds)
	/// to prevent orphaned locks if a process crashes between writing the lock token (step 2) and
	/// cleaning it up (after step 4).
	/// </para>
	/// <para>
	/// <strong>Performance:</strong> This operation performs 5 cache operations (1 get + 4 from TryRemoveAsync),
	/// so it has higher latency than native atomic operations. However, it works with any IDistributedCache
	/// implementation.
	/// </para>
	/// </remarks>
	/// <param name="cache">The distributed cache instance.</param>
	/// <param name="key">The key of the value to retrieve and remove.</param>
	/// <param name="lockTimeout">Duration after which the lock expires, 5 seconds if null.</param>
	/// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
	/// <returns>
	/// A task that completes when the operation finishes, containing the retrieved value if found and
	/// successfully removed; otherwise, null if the value was not found or another thread won the race.
	/// </returns>
	public static async Task<byte[]?> TryGetAndRemoveAsync(
		this IDistributedCache cache,
		string key,
		TimeSpan? lockTimeout = null,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(cache);
		ArgumentNullException.ThrowIfNull(key);

		// Get the value (return null if not found)
		var valueData = await cache.GetAsync(key, cancellationToken);
		if (valueData == null)
		{
			return null;
		}

		if (!await cache.TryRemoveAsync(key, lockTimeout, cancellationToken))
		{
			// Another thread's lock overwrote ours - they won the race
			return null;
		}

		// Our lock survived - we won the race, return the value
		return valueData;
	}

	/// <summary>
	/// Atomically attempts to remove a value from the distributed cache.
	/// Uses a lock-based protocol to ensure atomic removal semantics, preventing race conditions
	/// where multiple threads attempt to remove the same key concurrently.
	/// </summary>
	/// <remarks>
	/// <para><strong>Atomicity Protocol:</strong></para>
	/// <list type="number">
	///   <item><term>Step 1:</term> Write a unique lock token to fully-qualified lock key</item>
	///   <item><term>Step 2:</term> Remove the value from cache</item>
	///   <item><term>Step 3:</term> Read back the lock token and verify it matches ours</item>
	///   <item><term>Step 4:</term> Clean up the lock key</item>
	/// </list>
	/// <para>
	/// <strong>How it provides atomicity:</strong> In a race between multiple threads, only the thread whose
	/// lock token survives (last-write-wins) will return true. Other threads detect the lock mismatch
	/// and return false. What that leaves is spelled out below, because it is not the same answer on one
	/// node as on several.
	/// </para>
	/// <para>
	/// <strong>Use Case:</strong> This method is useful when you need to atomically remove a value without
	/// retrieving it (unlike <see cref="TryGetAndRemoveAsync"/>). For example, in the Device Authorization
	/// Grant flow when a user denies authorization, you only need confirmation that the request was removed,
	/// not the request data itself.
	/// </para>
	/// <para>
	/// <strong>What this guarantees:</strong> where ONE process touches the key, exactly one caller removes
	/// the value and every other caller is told the key was not there. Callers of this method on the same
	/// key are serialized in-process, so the protocol below never runs concurrently against itself. Note
	/// the condition is the key's traffic, not the deployment: a second process redeeming the same key at
	/// the same moment is outside this and lands in the paragraph below.
	/// </para>
	/// <para>
	/// <strong>Across processes it guarantees only AT MOST one.</strong> Two nodes redeeming the same key
	/// at the same moment can end with the value removed and neither told it took it, because the lock
	/// protocol is assembled from <c>Get</c>, <c>Set</c> and <c>Remove</c> as three separate operations and
	/// there is a window between any two of them. A take-once needs one indivisible read-modify-write, and
	/// this interface exposes none: no compare-and-swap, no set-if-absent, no delete-returning-value.
	/// </para>
	/// <para>
	/// <strong>A deployment on several nodes that cannot afford that</strong> supplies its own storage and
	/// reaches for the primitive its store already has. No new API is needed for that:
	/// <c>IDeviceAuthorizationStorage</c>, <c>IBackChannelRequestStorage</c> and <c>IEntityStorage</c> are
	/// public and registered with <c>TryAddSingleton</c>, so a host's own registration wins. Which
	/// primitive to reach for depends on the store, which is why it cannot be chosen here:
	/// </para>
	/// <list type="bullet">
	///   <item>Redis 6.2 and later: <c>GETDEL key</c>, one command, which returns the value to exactly one
	///   caller and deletes it. Earlier versions get the same effect from a two-line <c>EVAL</c> script,
	///   since Redis runs a script indivisibly. Both are for a storage of your own: they read a STRING,
	///   and the <c>IDistributedCache</c> implementation for Redis keeps each entry as a hash whose value
	///   sits in a field, so pointed at these keys they answer <c>WRONGTYPE</c>.</item>
	///   <item>PostgreSQL: <c>DELETE FROM ... WHERE key = $1 RETURNING value</c>. The row lock picks the
	///   winner, and at the default isolation level the loser returns no rows; under REPEATABLE READ or
	///   SERIALIZABLE it fails to serialize instead, which is the same answer through an exception.</item>
	///   <item>SQL Server: <c>DELETE ... OUTPUT deleted.value</c>, the same shape.</item>
	///   <item>Oracle: <c>DELETE ... RETURNING value INTO :out</c>. Oracle documents the RETURNING INTO
	///   clause as belonging to DELETE among others, and for a DELETE it yields the pre-deletion value.</item>
	/// </list>
	/// <para>
	/// <strong>Lock timeout:</strong> Locks auto-expire after the specified timeout (default 5 seconds)
	/// to prevent orphaned locks if a process crashes between writing the lock token and cleaning it up.
	/// </para>
	/// </remarks>
	/// <param name="cache">The distributed cache instance.</param>
	/// <param name="key">The key of the value to remove.</param>
	/// <param name="lockTimeout">Duration after which the lock expires, 5 seconds if null.</param>
	/// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
	/// <returns>
	/// A task that completes when the operation finishes, containing true if the value was removed by this
	/// caller; false if another caller took it, if the key did not exist, or - only across processes - if
	/// the value was removed and no caller could be told it took it.
	/// </returns>
	public static async Task<bool> TryRemoveAsync(
		this IDistributedCache cache,
		string key,
		TimeSpan? lockTimeout = null,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(cache);
		ArgumentNullException.ThrowIfNull(key);

		// Redemptions of the SAME key are serialized within this process, so the protocol below never runs
		// concurrently against itself here and the interleaving that loses a value cannot form. Callers on
		// different keys never meet: the gate exists only while a call is in flight and is discarded with
		// the last one out.
		//
		// This gate is taken HERE and not in TryGetAndRemoveAsync, which calls this method - gating both
		// would deadlock a caller against itself on one key. That is safe: TryGetAndRemoveAsync discards
		// the value it read whenever this returns false, so a caller that lost inside the gate hands back
		// nothing.
		var gate = RentGate(key);
		try
		{
			await gate.WaitAsync(cancellationToken);
			try
			{
				return await RemoveUnderGateAsync(cache, key, lockTimeout, cancellationToken);
			}
			finally
			{
				gate.Release();
			}
		}
		finally
		{
			ReturnGate(key);
		}
	}

	/// <summary>
	/// One gate per key, alive only while a redemption of that key is in flight.
	/// </summary>
	/// <remarks>
	/// Retired on the way out, unlike the per-stream gate in the security-event outbox, and the difference
	/// is the key space rather than taste: a stream is a long-lived entity and its gates are bounded by how
	/// many exist, while these are keyed by the code being redeemed, so a table that never forgets would
	/// grow by one entry for every authorization the deployment ever issues.
	/// </remarks>
	/// <remarks>
	/// Internal rather than private so the test that proves it is emptied can name it and be carried
	/// through a rename by the compiler. Read-only from outside this class either way.
	/// </remarks>
	internal static readonly Dictionary<string, GateEntry> Gates = new(StringComparer.Ordinal);

	internal sealed class GateEntry
	{
		public readonly SemaphoreSlim Gate = new(1, 1);
		public int Waiters;
	}

	private static SemaphoreSlim RentGate(string key)
	{
		lock (Gates)
		{
			if (!Gates.TryGetValue(key, out var entry))
			{
				entry = new GateEntry();
				Gates[key] = entry;
			}

			// Incremented before the caller waits, so nobody else can retire this gate underneath it.
			entry.Waiters++;
			return entry.Gate;
		}
	}

	private static void ReturnGate(string key)
	{
		lock (Gates)
		{
			// Loud rather than defensive: every return is paired with a rent that put the entry here, so a
			// miss means the invariant is already broken and swallowing it hides whatever broke it.
			if (!Gates.TryGetValue(key, out var entry))
				throw new InvalidOperationException($"No redemption gate is held for '{key}'.");

			if (--entry.Waiters > 0)
				return;

			// The last caller out retires the gate, which is what keeps the table the size of the traffic
			// in flight rather than the size of every key ever redeemed.
			Gates.Remove(key);
			entry.Gate.Dispose();
		}
	}

	private static async Task<bool> RemoveUnderGateAsync(
		IDistributedCache cache,
		string key,
		TimeSpan? lockTimeout,
		CancellationToken cancellationToken)
	{
		// Use fully qualified type name to avoid collisions with application keys
		var lockKey = $"{nameof(Abblix)}.{nameof(Utils)}.{nameof(DistributedCacheExtensions)}:{nameof(TryRemoveAsync)}:{key}";

		// Write our unique lock token
		var ourLockToken = Guid.NewGuid().ToByteArray();
		await cache.SetAsync(
			lockKey,
			ourLockToken,
			new () { AbsoluteExpirationRelativeToNow = lockTimeout ?? TimeSpan.FromSeconds(5) },
			cancellationToken);

		// The value must still exist at the moment we hold the lock. Without this check a caller whose lock
		// window does not overlap a prior successful removal would still see its own token survive and wrongly
		// report success - breaking exactly-once removal (two token requests both redeeming the same
		// device_code or authorization code). RFC 6749 §4.1.2 forbids reusing an authorization code; for a
		// device_code no RFC says so, and single use is this codebase's own rule. The documented contract is
		// "false if ... the key didn't exist".
		if (await cache.GetAsync(key, cancellationToken) == null)
		{
			await cache.RemoveAsync(lockKey, cancellationToken); // clean up our lock
			return false;
		}

		// Remove the value
		await cache.RemoveAsync(key, cancellationToken);

		// Verify our lock token survived (last-write-wins check)
		var survivingLockToken = await cache.GetAsync(lockKey, cancellationToken);
		if (survivingLockToken == null || !ourLockToken.SequenceEqual(survivingLockToken))
		{
			// Another thread's lock overwrote ours - they won the race
			return false;
		}

		// Our lock survived - we won the race, return the value
		await cache.RemoveAsync(lockKey, cancellationToken); // Cleanup lock
		return true;
	}
}
