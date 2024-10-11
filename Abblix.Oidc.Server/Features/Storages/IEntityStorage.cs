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
    /// <returns>A task that represents the asynchronous operation, providing awareness of completion or faults.
    /// </returns>
    Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null);

    /// <summary>
    /// Asynchronously retrieves an entity of specified type from the storage.
    /// </summary>
    /// <typeparam name="T">The type of the entity to retrieve.</typeparam>
    /// <param name="key">The unique cache key associated with the entity to retrieve.</param>
    /// <param name="removeOnRetrieval">Indicates whether the entity should be removed from the storage after retrieval.
    /// </param>
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
