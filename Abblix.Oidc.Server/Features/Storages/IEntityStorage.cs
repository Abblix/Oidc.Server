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

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides an interface for a storage mechanism that can store entities of various types persistently.
/// This interface enables asynchronous interactions with the underlying storage system, allowing
/// operations such as adding, retrieving, and removing entities with flexible caching strategies.
/// </summary>
public interface IEntityStorage
{
    /// <summary>
    /// Asynchronously adds an entity to the storage with the specified cache entry options.
    /// </summary>
    /// <typeparam name="T">The type of the entity to cache.</typeparam>
    /// <param name="key">The unique cache key used to store and retrieve the value.</param>
    /// <param name="value">The entity to be stored in the cache.</param>
    /// <param name="options">Configuration options for the cache entry, such as expiration times.</param>
    /// <param name="token">An optional cancellation token that can be used to cancel the storage operation.</param>
    /// <returns>A task that represents the asynchronous operation, providing awareness of completion or faults.</returns>
    Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null);

    /// <summary>
    /// Asynchronously retrieves an entity of specified type from the storage.
    /// </summary>
    /// <typeparam name="T">The type of the entity to retrieve.</typeparam>
    /// <param name="key">The unique cache key associated with the entity to retrieve.</param>
    /// <param name="removeOnRetrieval">Indicates whether the entity should be removed from the storage after retrieval.</param>
    /// <param name="token">An optional cancellation token that can be used to cancel the retrieval operation.</param>
    /// <returns>A task that returns the retrieved entity, if found, or null if no entity is found.</returns>
    Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null);

    /// <summary>
    /// Asynchronously removes an entity from the storage.
    /// </summary>
    /// <param name="key">The unique cache key associated with the entity to be removed.</param>
    /// <param name="token">An optional cancellation token that can be used to cancel the removal operation.</param>
    /// <returns>A task that represents the asynchronous operation of removing the entity.</returns>
    Task RemoveAsync(string key, CancellationToken? token = null);
}
