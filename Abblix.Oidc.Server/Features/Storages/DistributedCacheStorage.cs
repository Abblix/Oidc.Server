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

using Abblix.Oidc.Server.Common.Interfaces;
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

		var result = await cache.GetAsync(key, token.Value);
		if (result == null)
		{
			return default;
		}

		var deserializedResult = serializer.Deserialize<T>(result);

		if (removeOnRetrieval)
		{
			await cache.RemoveAsync(key, token.Value);
		}

		return deserializedResult;
	}

	/// <summary>
	/// Asynchronously removes an object from the distributed cache.
	/// </summary>
	/// <param name="key">The key of the object to remove.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>A task that completes when the operation finishes.of removing the object.</returns>
	public Task RemoveAsync(string key, CancellationToken? token = null)
		=> cache.RemoveAsync(key, token ?? CancellationToken.None);
}
