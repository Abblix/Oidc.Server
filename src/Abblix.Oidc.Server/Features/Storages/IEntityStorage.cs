// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Key/value storage abstraction over short-lived OIDC entities (authorization codes, PAR
/// requests, CIBA/device authorization records, JWT statuses, rate-limit counters). Each entry
/// has an expiration policy expressed via <see cref="StorageOptions"/>; implementations may be
/// in-process or distributed.
/// </summary>
/// <remarks>
/// Implementations must support atomic get-and-remove semantics when
/// <c>removeOnRetrieval</c> is true so that single-use credentials (authorization codes, PAR
/// request URIs) cannot be replayed across concurrent token requests.
/// </remarks>
public interface IEntityStorage
{
    /// <summary>
    /// Stores an entity under <paramref name="key"/>, replacing any existing value, with the
    /// expiration behavior described by <paramref name="options"/>.
    /// </summary>
    /// <typeparam name="T">The type of the entity to store.</typeparam>
    /// <param name="key">The unique key used to store and later retrieve the value.</param>
    /// <param name="value">The entity to store.</param>
    /// <param name="options">Expiration policy for the stored entry.</param>
    /// <param name="token">An optional cancellation token.</param>
    /// <returns>A task that completes once the entity has been written.</returns>
    Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null);

    /// <summary>
    /// Retrieves the entity stored under <paramref name="key"/>, optionally deleting it
    /// atomically as part of the same operation to enforce single-use semantics.
    /// </summary>
    /// <typeparam name="T">The type of the entity to retrieve.</typeparam>
    /// <param name="key">The key associated with the entity.</param>
    /// <param name="removeOnRetrieval">When true, the entry must be removed atomically with the
    /// read so that a concurrent caller cannot observe the same value.</param>
    /// <param name="token">An optional cancellation token.</param>
    /// <returns>
    /// The stored entity, or <c>null</c>. With <paramref name="removeOnRetrieval"/> set, null does not
    /// mean the entry was absent: the removal is a protocol over a store with no indivisible
    /// read-modify-write, so it also covers another caller having taken it, a claim that expired while a
    /// store call was in flight, and the entry being gone with nobody able to be told they took it.
    /// </returns>
    Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null);

    /// <summary>
    /// Removes the entity stored under <paramref name="key"/>; succeeds silently when no entry
    /// is present.
    /// </summary>
    /// <param name="key">The key of the entity to remove.</param>
    /// <param name="token">An optional cancellation token.</param>
    /// <returns>A task that completes once the removal request has been processed.</returns>
    Task RemoveAsync(string key, CancellationToken? token = null);
}
