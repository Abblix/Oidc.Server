// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides a general-purpose distributed caching mechanism with serialization support,
/// enabling the storage and retrieval of any type of serialized objects.
/// </summary>
public sealed class DistributedCacheStorage : IEntityStorage
{
	/// <summary>
	/// Initializes a new instance of the <see cref="DistributedCacheStorage"/> class.
	/// </summary>
	/// <param name="cache">The distributed cache backend used for storing and retrieving data.</param>
	/// <param name="serializer">The serializer used for converting objects to and from binary format.</param>
	public DistributedCacheStorage(IDistributedCache cache, IBinarySerializer serializer)
	{
		_cache = cache;
		_serializer = serializer;
	}

	private readonly IDistributedCache _cache;
	private readonly IBinarySerializer _serializer;

	/// <summary>
	/// Asynchronously stores an object in the distributed cache.
	/// </summary>
	/// <typeparam name="T">The type of the object to store.</typeparam>
	/// <param name="key">The key under which the object is stored.</param>
	/// <param name="value">The object to store.</param>
	/// <param name="options">Configuration options for the cache entry, such as expiration.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation.</returns>
	public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
	{
		ArgumentNullException.ThrowIfNull(key);
		return _cache.SetAsync(
			key,
			_serializer.Serialize(value),
			new DistributedCacheEntryOptions
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
	/// <returns>A task that represents the asynchronous operation, containing the retrieved object, if found;
	/// otherwise, null.</returns>
	public async Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
	{
		ArgumentNullException.ThrowIfNull(key);
		token ??= CancellationToken.None;

		var result = await _cache.GetAsync(key, token.Value);
		if (result == null)
		{
			return default;
		}

		var deserializedResult = _serializer.Deserialize<T>(result);

		if (removeOnRetrieval)
		{
			await _cache.RemoveAsync(key, token.Value);
		}

		return deserializedResult;
	}

	/// <summary>
	/// Asynchronously removes an object from the distributed cache.
	/// </summary>
	/// <param name="key">The key of the object to remove.</param>
	/// <param name="token">An optional cancellation token to cancel the operation.</param>
	/// <returns>A task that represents the asynchronous operation of removing the object.</returns>
	public Task RemoveAsync(string key, CancellationToken? token = null)
		=> _cache.RemoveAsync(key, token ?? CancellationToken.None);
}
