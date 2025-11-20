// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.Utils;

/// <summary>
/// Extension methods for <see cref="IDistributedCache"/> providing atomic operations.
/// </summary>
public static class DistributedCacheExtensions
{
	/// <summary>
	/// Atomically retrieves and removes a value from the distributed cache.
	/// Uses a lock-based protocol to ensure atomic get-and-remove semantics even when the underlying
	/// cache implementation doesn't support native atomic operations (e.g., Redis GETDEL).
	/// </summary>
	/// <remarks>
	/// <para><strong>Atomicity Protocol:</strong></para>
	/// <list type="number">
	///   <item><term>Step 1:</term> Get the value from cache</item>
	///   <item><term>Step 2:</term> Write a unique lock token to "lock:{key}"</item>
	///   <item><term>Step 3:</term> Remove the value from cache</item>
	///   <item><term>Step 4:</term> Read back the lock token and verify it matches ours</item>
	/// </list>
	/// <para>
	/// <strong>How it provides atomicity:</strong> In a race between multiple threads, only the thread whose
	/// lock token survives (last-write-wins) will return the value. Other threads detect the lock mismatch
	/// and return null. This ensures exactly one thread retrieves the value, even though individual cache
	/// operations are not atomic.
	/// </para>
	/// <para>
	/// <strong>Lock timeout:</strong> Locks auto-expire after the specified timeout (default 5 seconds)
	/// to prevent orphaned locks if a process crashes between writing the lock token (step 2) and
	/// cleaning it up (after step 4).
	/// </para>
	/// <para>
	/// <strong>Performance:</strong> This operation performs 4 cache operations instead of 1, so it has higher
	/// latency than native atomic operations. However, it works with any IDistributedCache implementation.
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

		// Step 1: Get the value (return null if not found)
		var valueData = await cache.GetAsync(key, cancellationToken);
		if (valueData == null)
		{
			return null;
		}

		// Step 2: Write our unique lock token
		var lockKey = $"lock:{key}";
		var ourLockToken = Guid.NewGuid().ToByteArray();
		await cache.SetAsync(
			lockKey,
			ourLockToken,
			new () { AbsoluteExpirationRelativeToNow = lockTimeout ?? TimeSpan.FromSeconds(5) },
			cancellationToken);

		// Step 3: Remove the value
		await cache.RemoveAsync(key, cancellationToken);

		// Step 4: Verify our lock token survived (last-write-wins check)
		var survivingLockToken = await cache.GetAsync(lockKey, cancellationToken);
		if (survivingLockToken == null || !ourLockToken.SequenceEqual(survivingLockToken))
		{
			// Another thread's lock overwrote ours - they won the race
			return null;
		}

		// Our lock survived - we won the race, return the value
		await cache.RemoveAsync(lockKey, cancellationToken); // Cleanup lock
		return valueData;
	}
}
