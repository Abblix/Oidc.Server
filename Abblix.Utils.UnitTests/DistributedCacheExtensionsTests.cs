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

using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Tests for <see cref="DistributedCacheExtensions.TryGetAndRemoveAsync"/>.
/// Verifies the atomic get-and-remove protocol prevents race conditions in concurrent scenarios.
/// </summary>
public class DistributedCacheExtensionsTests
{
	private static IDistributedCache CreateCache()
	{
		var options = Options.Create(new MemoryDistributedCacheOptions());
		return new MemoryDistributedCache(options);
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_ValueExists_ReturnsValueAndRemovesIt()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "test-key";
		var value = Encoding.UTF8.GetBytes("test-value");
		await cache.SetAsync(key, value);

		// Act
		var result = await cache.TryGetAndRemoveAsync(key);

		// Assert
		Assert.NotNull(result);
		Assert.Equal(value, result);

		// Verify value was removed
		var afterRemove = await cache.GetAsync(key);
		Assert.Null(afterRemove);
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_ValueDoesNotExist_ReturnsNull()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "nonexistent-key";

		// Act
		var result = await cache.TryGetAndRemoveAsync(key);

		// Assert
		Assert.Null(result);
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_ConcurrentCalls_OnlyOneSucceeds()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "concurrent-key";
		var value = Encoding.UTF8.GetBytes("concurrent-value");
		await cache.SetAsync(key, value);

		// Act - simulate race condition with 10 concurrent threads
		var tasks = Enumerable.Range(0, 10)
			.Select(_ => cache.TryGetAndRemoveAsync(key))
			.ToArray();

		var results = await Task.WhenAll(tasks);

		// Assert - exactly one thread should succeed
		var successfulResults = results.Where(r => r != null).ToArray();
		Assert.Single(successfulResults);
		Assert.Equal(value, successfulResults[0]);

		// All other results should be null
		Assert.Equal(9, results.Count(r => r == null));

		// Verify value was removed
		var afterRemove = await cache.GetAsync(key);
		Assert.Null(afterRemove);
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_LockExpires_DoesNotLeakLocks()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "lock-expiry-key";
		var value = Encoding.UTF8.GetBytes("lock-expiry-value");
		await cache.SetAsync(key, value);

		// Act
		var result = await cache.TryGetAndRemoveAsync(key);

		// Assert - operation succeeded
		Assert.NotNull(result);
		Assert.Equal(value, result);

		// Wait for lock to expire (5 seconds + buffer)
		await Task.Delay(TimeSpan.FromSeconds(6));

		// Verify lock was cleaned up (either explicitly or via expiration)
		var lockKey = $"lock:{key}";
		var lockValue = await cache.GetAsync(lockKey);
		Assert.Null(lockValue);
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_MultipleKeys_IndependentOperations()
	{
		// Arrange
		var cache = CreateCache();
		const string key1 = "key1";
		const string key2 = "key2";
		var value1 = Encoding.UTF8.GetBytes("value1");
		var value2 = Encoding.UTF8.GetBytes("value2");
		await cache.SetAsync(key1, value1);
		await cache.SetAsync(key2, value2);

		// Act - concurrent operations on different keys
		var task1 = cache.TryGetAndRemoveAsync(key1);
		var task2 = cache.TryGetAndRemoveAsync(key2);
		var results = await Task.WhenAll(task1, task2);

		// Assert - both should succeed independently
		Assert.NotNull(results[0]);
		Assert.NotNull(results[1]);
		Assert.Equal(value1, results[0]);
		Assert.Equal(value2, results[1]);

		// Verify both values were removed
		Assert.Null(await cache.GetAsync(key1));
		Assert.Null(await cache.GetAsync(key2));
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_EmptyValue_ReturnsEmptyArray()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "empty-key";
		var emptyValue = Array.Empty<byte>();
		await cache.SetAsync(key, emptyValue);

		// Act
		var result = await cache.TryGetAndRemoveAsync(key);

		// Assert
		Assert.NotNull(result);
		Assert.Empty(result);

		// Verify value was removed
		var afterRemove = await cache.GetAsync(key);
		Assert.Null(afterRemove);
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_CancellationToken_PassedToUnderlyingOperations()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "cancellation-key";
		var value = Encoding.UTF8.GetBytes("cancellation-value");
		await cache.SetAsync(key, value);
		var cts = new CancellationTokenSource();

		// Act - verify method accepts cancellation token without throwing
		var result = await cache.TryGetAndRemoveAsync(key, cancellationToken: cts.Token);

		// Assert - operation should complete successfully
		Assert.NotNull(result);
		Assert.Equal(value, result);
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_NullCache_ThrowsArgumentNullException()
	{
		// Arrange
		IDistributedCache? cache = null;

		// Act & Assert
		await Assert.ThrowsAsync<ArgumentNullException>(async () =>
			await cache!.TryGetAndRemoveAsync("key"));
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_NullKey_ThrowsArgumentNullException()
	{
		// Arrange
		var cache = CreateCache();

		// Act & Assert
		await Assert.ThrowsAsync<ArgumentNullException>(async () =>
			await cache.TryGetAndRemoveAsync(null!));
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_HighConcurrency_AllButOneThreadLose()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "high-concurrency-key";
		var value = Encoding.UTF8.GetBytes("high-concurrency-value");
		await cache.SetAsync(key, value);

		// Act - simulate high concurrency with 100 threads
		var tasks = Enumerable.Range(0, 100)
			.Select(_ => cache.TryGetAndRemoveAsync(key))
			.ToArray();

		var results = await Task.WhenAll(tasks);

		// Assert - exactly one thread wins
		var winners = results.Where(r => r != null).ToArray();
		Assert.Single(winners);
		Assert.Equal(value, winners[0]);

		// All losers get null
		Assert.Equal(99, results.Count(r => r == null));
	}

	[Fact]
	public async Task TryGetAndRemoveAsync_SequentialCalls_SecondCallReturnsNull()
	{
		// Arrange
		var cache = CreateCache();
		const string key = "sequential-key";
		var value = Encoding.UTF8.GetBytes("sequential-value");
		await cache.SetAsync(key, value);

		// Act
		var firstResult = await cache.TryGetAndRemoveAsync(key);
		var secondResult = await cache.TryGetAndRemoveAsync(key);

		// Assert
		Assert.NotNull(firstResult);
		Assert.Equal(value, firstResult);
		Assert.Null(secondResult);
	}
}
