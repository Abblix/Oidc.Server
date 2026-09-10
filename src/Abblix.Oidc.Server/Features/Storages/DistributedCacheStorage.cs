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
/// <param name="takeOnceStore">A store able to take a value and delete it indivisibly, when
/// the host registered one. Absent, the redemption keeps the in-process guarantee and no more.</param>
public sealed class DistributedCacheStorage(
	IDistributedCache cache,
	IBinarySerializer serializer,
	ITakeOnceStore? takeOnceStore = null) : IEntityStorage
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
	/// When removeOnRetrieval is true, uses atomic get-and-remove operation via
	/// <see cref="Abblix.Utils.DistributedCacheExtensions.TryGetAndRemoveAsync"/>.
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

		byte[]? result;
		if (!removeOnRetrieval)
		{
			result = await cache.GetAsync(key, token.Value);
		}
		else if (takeOnceStore is not null)
		{
			// A store that can take and delete in one step is asked to, because that is the only way the
			// redemption is exactly-once across processes.
			result = await takeOnceStore.TryTakeAsync(key, token.Value);
		}
		else
		{
			// Without one the extension keeps the answer it has: serialized within this process, and
			// probabilistic beyond it.
			result = await cache.TryGetAndRemoveAsync(key, cancellationToken: token.Value);
		}

		return result != null ? serializer.Deserialize<T>(result) : default;
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
