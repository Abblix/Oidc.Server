// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides a general-purpose distributed caching mechanism with serialization support,
/// enabling the storage and retrieval of serialized objects.
/// </summary>
/// <param name="cache">The distributed cache backend used for storing and retrieving data.</param>
/// <param name="serializer">The serializer used for converting objects to and from binary format.</param>
public sealed class DistributedCacheStorage(IDistributedCache cache, IBinarySerializer serializer) : IEntityStorage
{
	/// <summary>
	/// Asynchronously stores an object in the distributed cache.
	/// </summary>
	/// <typeparam name="T">The type of the object to store.</typeparam>
	/// <param name="key">The key under which the object is stored.</param>
	/// <param name="value">The object to store.</param>
	/// <param name="options">Configuration options for the cache entry, such as expiration.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>A task that completes when the operation finishes.</returns>
	public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
	{
		ArgumentNullException.ThrowIfNull(key);
		return cache.SetAsync(
			key,
			serializer.Serialize(value),
			new ()
			{
				AbsoluteExpiration = options.AbsoluteExpiration,
				AbsoluteExpirationRelativeToNow = options.AbsoluteExpirationRelativeToNow,
				SlidingExpiration = options.SlidingExpiration,
			},
			token ?? CancellationToken.None);
	}

	/// <summary>
	/// Asynchronously retrieves an object from the distributed cache.
	/// When removeOnRetrieval is true, claims the entry through
	/// <see cref="Abblix.Utils.DistributedCacheExtensions.TryGetAndRemoveAsync"/>, which is indivisible
	/// WITHIN THIS PROCESS and no further: the read and the removal happen under one hold of a per-key
	/// gate that a second instance cannot see, so two of them can be handed the same value. Closing that
	/// is the job of a storage whose backing store decides the claim in one command, which is what
	/// <see cref="IEntityStorage"/> asks implementations for and what this one cannot give.
	/// </summary>
	/// <typeparam name="T">The type of the object to retrieve.</typeparam>
	/// <param name="key">The key associated with the object to retrieve.</param>
	/// <param name="removeOnRetrieval">Whether to remove the object from the cache after retrieval.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>A task that completes when the operation finishes. containing the retrieved object, if found;
	/// otherwise, null.</returns>
	public async Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
	{
		ArgumentNullException.ThrowIfNull(key);
		token ??= CancellationToken.None;

		var result = removeOnRetrieval
			? await cache.TryGetAndRemoveAsync(key, cancellationToken: token.Value)
			: await cache.GetAsync(key, token.Value);

		return result != null ? serializer.Deserialize<T>(result) : default;
	}

	/// <summary>
	/// Claims a key by writing to it only when it carries nothing, through
	/// <see cref="Abblix.Utils.DistributedCacheExtensions.TrySetIfAbsentAsync"/> - which decides the
	/// winner WITHIN THIS PROCESS and no further, the read and the write happening under one hold of a
	/// per-key gate a second instance cannot see. A deployment spread over several nodes supplies its own
	/// storage and uses the primitive its store already has.
	/// </summary>
	/// <typeparam name="T">The type of the object to store.</typeparam>
	/// <param name="key">The key to claim.</param>
	/// <param name="value">The object to store when the key is free.</param>
	/// <param name="options">Configuration options for the cache entry, such as expiration.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>True when this caller wrote the value; false when a value was already there.</returns>
	public Task<bool> TrySetIfAbsentAsync<T>(
		string key, T value, StorageOptions options, CancellationToken? token = null)
	{
		ArgumentNullException.ThrowIfNull(key);
		return cache.TrySetIfAbsentAsync(
			key,
			serializer.Serialize(value),
			new ()
			{
				AbsoluteExpiration = options.AbsoluteExpiration,
				AbsoluteExpirationRelativeToNow = options.AbsoluteExpirationRelativeToNow,
				SlidingExpiration = options.SlidingExpiration,
			},
			token ?? CancellationToken.None);
	}

	/// <summary>
	/// Replaces an entry only when it still holds what the caller read, through
	/// <see cref="Abblix.Utils.DistributedCacheExtensions.TryReplaceAsync"/> under the per-key gate, so it is
	/// decided WITHIN THIS PROCESS and no further.
	/// </summary>
	/// <remarks>
	/// What the key holds is read back and written again by this serializer before it is compared with the
	/// expected value written the same way, so two encodings of one value, such as a field written out at its
	/// default by another writer, compare equal. Compared as stored bytes they would never match, and a caller
	/// retrying until its replace succeeds would never stop.
	/// </remarks>
	/// <typeparam name="T">The type of the object to store.</typeparam>
	/// <param name="key">The key whose value is replaced.</param>
	/// <param name="expected">The object the caller read.</param>
	/// <param name="value">The object to store in its place.</param>
	/// <param name="options">Configuration options for the cache entry, such as expiration.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>True when the key held the expected object and this caller replaced it; false otherwise.</returns>
	public Task<bool> TryReplaceAsync<T>(
		string key, T expected, T value, StorageOptions options, CancellationToken? token = null)
	{
		ArgumentNullException.ThrowIfNull(key);
		var expectedBytes = serializer.Serialize(expected);
		return cache.TryReplaceAsync(
			key,
			current => serializer.Deserialize<T>(current) is { } read
				&& serializer.Serialize(read).AsSpan().SequenceEqual(expectedBytes),
			serializer.Serialize(value),
			new ()
			{
				AbsoluteExpiration = options.AbsoluteExpiration,
				AbsoluteExpirationRelativeToNow = options.AbsoluteExpirationRelativeToNow,
				SlidingExpiration = options.SlidingExpiration,
			},
			token ?? CancellationToken.None);
	}

	/// <summary>
	/// Gives an entry a new expiration policy through
	/// <see cref="Abblix.Utils.DistributedCacheExtensions.TryExtendAsync"/>, which reads the value and writes
	/// it straight back under the per-key gate, so it is decided WITHIN THIS PROCESS and no further.
	/// </summary>
	/// <param name="key">The key whose entry is kept longer.</param>
	/// <param name="options">The new expiration policy.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>True when the key held an entry and it now carries the new policy; false when it held none.
	/// </returns>
	public Task<bool> TryExtendAsync(string key, StorageOptions options, CancellationToken? token = null)
	{
		ArgumentNullException.ThrowIfNull(key);
		return cache.TryExtendAsync(
			key,
			new ()
			{
				AbsoluteExpiration = options.AbsoluteExpiration,
				AbsoluteExpirationRelativeToNow = options.AbsoluteExpirationRelativeToNow,
				SlidingExpiration = options.SlidingExpiration,
			},
			token ?? CancellationToken.None);
	}

	/// <summary>
	/// Asynchronously removes an object from the distributed cache.
	/// </summary>
	/// <param name="key">The key of the object to remove.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>A task that completes when the removal has been issued to the cache.</returns>
	public Task RemoveAsync(string key, CancellationToken? token = null)
		=> cache.RemoveAsync(key, token ?? CancellationToken.None);
}
