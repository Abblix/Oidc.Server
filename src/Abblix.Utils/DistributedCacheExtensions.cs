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
	/// <strong>What it guarantees, and what it does not:</strong> in a race, only the caller whose lock
	/// token survives last-write-wins returns the value; the others detect the mismatch and return null.
	/// AT MOST one caller ever retrieves it, never two. NOT exactly one: a caller can remove the value and
	/// then find a later caller's lock in place, in which case the value is gone and neither caller is told
	/// it took it. Nothing observes that from inside a call - the losing caller cannot tell whether anybody
	/// else won - so it is not reported, only documented. Issue 435 carries the fix, which needs an
	/// indivisible take this interface does not expose.
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
	/// and return false. So AT MOST one caller ever removes the value, never two - but not exactly one: a
	/// caller that removes it and then finds a later caller's lock in place reports a loss over a value
	/// that is already gone, and so does the other. Issue 435 carries the fix.
	/// </para>
	/// <para>
	/// <strong>Use Case:</strong> This method is useful when you need to atomically remove a value without
	/// retrieving it (unlike <see cref="TryGetAndRemoveAsync"/>). For example, in the Device Authorization
	/// Grant flow when a user denies authorization, you only need confirmation that the request was removed,
	/// not the request data itself.
	/// </para>
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
	/// A task that completes when the operation finishes, containing true if the value was successfully
	/// removed by this thread; false if another thread won the race or the key didn't exist.
	/// </returns>
	public static async Task<bool> TryRemoveAsync(
		this IDistributedCache cache,
		string key,
		TimeSpan? lockTimeout = null,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(cache);
		ArgumentNullException.ThrowIfNull(key);

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
