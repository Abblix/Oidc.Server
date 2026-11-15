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
/// <para>
/// Implementations must support atomic get-and-remove semantics when
/// <c>removeOnRetrieval</c> is true so that single-use credentials (authorization codes, PAR
/// request URIs) cannot be replayed across concurrent token requests.
/// </para>
/// <para>
/// Every operation that decides between callers - the read with removal,
/// <see cref="TrySetIfAbsentAsync{T}"/>, <see cref="TryReplaceAsync{T}"/> and <see cref="TryExtendAsync"/> -
/// is exactly as atomic as the store behind it makes it. The shipped <see cref="DistributedCacheStorage"/>
/// rides <c>IDistributedCache</c>, which has no conditional write, so it decides between the callers of one
/// process under a per-key gate; two requests that reach different nodes can both be told they came first.
/// A deployment with several nodes registers a storage that maps each of these operations to one command of
/// its store, so the decision is made by the store and holds for every node. In Redis:
/// </para>
/// <list type="bullet">
/// <item><description><see cref="TrySetIfAbsentAsync{T}"/> is <c>SET key value NX PX ttl</c>, writing the
/// value and its lifetime together, so no key is ever left without its expiry.</description></item>
/// <item><description>The read with removal is <c>GETDEL</c>.</description></item>
/// <item><description><see cref="TryExtendAsync"/> is <c>PEXPIRE</c> or <c>PEXPIREAT</c>, which leave a key
/// that is gone alone.</description></item>
/// <item><description><see cref="TryReplaceAsync{T}"/> is a short script that compares and writes in one
/// step, comparing values as that method requires.</description></item>
/// </list>
/// <para>
/// With such a storage, the decisions built on these operations hold across nodes as well: the logout
/// confirmation question two overlapping end-session requests share, the reuse check of a PKCE code challenge
/// or a nonce, the end of a pushed authorization flow, single-use codes and request URIs, and the token
/// registry. Other stores offer the same primitive: SQL <c>INSERT ... ON CONFLICT DO NOTHING</c> on a row
/// carrying its expiry, a conditional put with <c>attribute_not_exists</c> and a TTL attribute in DynamoDB, a
/// create that fails on an existing id in Cosmos DB, an etcd transaction on a key's create revision with a
/// lease. Replay detection of presented tokens (DPoP proofs, client assertions, security event tokens) is not
/// kept here: it goes through <c>IReplayCache</c>, which takes its own implementation of the same primitive.
/// </para>
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
    /// <returns>The stored entity, or <c>null</c> when no entry is present or it has expired.</returns>
    Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null);

    /// <summary>
    /// Writes an entity only when <paramref name="key"/> carries none, and reports whether this caller
    /// is the one that wrote it.
    /// </summary>
    /// <remarks>
    /// Implementations must decide this between concurrent callers: of several racing for one key, at
    /// most one may be told it wrote. This is what lets a count be kept without reading a number and
    /// writing it back - each event claims a key of its own, and two events arriving together claim two
    /// keys instead of writing the same number twice.
    /// </remarks>
    /// <typeparam name="T">The type of the entity to store.</typeparam>
    /// <param name="key">The key to claim.</param>
    /// <param name="value">The entity to store when the key is free.</param>
    /// <param name="options">Expiration policy for the entry, when one is written.</param>
    /// <param name="token">An optional cancellation token.</param>
    /// <returns>
    /// True when the key held nothing and this caller wrote the value; false when a value was already
    /// there.
    /// </returns>
    Task<bool> TrySetIfAbsentAsync<T>(
        string key, T value, StorageOptions options, CancellationToken? token = null);

    /// <summary>
    /// Writes an entity only when <paramref name="key"/> still carries <paramref name="expected"/>, and reports
    /// whether this caller is the one that wrote it.
    /// </summary>
    /// <remarks>
    /// Implementations must decide this between concurrent callers: of several that read the same value and race
    /// to replace it, at most one may be told it wrote, and a key that holds nothing, or a value another caller has
    /// written since, is left as it is. This is what lets a record only ever move one way, such as a revocation
    /// cutoff that must never be moved back: the caller reads it, decides, and replaces it only if nobody changed it
    /// in between, or reads it again.
    /// <para>
    /// The other half is as binding: when nobody has written since the caller read, the caller must be told it
    /// wrote. The comparison is therefore of values, not of stored bytes - a value read and written again need not
    /// come back as the bytes another writer stored for it - and a replace that can never match leaves a caller
    /// that reads again and retries unable to record anything at all.
    /// </para>
    /// </remarks>
    /// <typeparam name="T">The type of the entity to store.</typeparam>
    /// <param name="key">The key whose value is replaced.</param>
    /// <param name="expected">The value the caller read and decided on.</param>
    /// <param name="value">The entity to store in its place.</param>
    /// <param name="options">Expiration policy for the entry, when one is written.</param>
    /// <param name="token">An optional cancellation token.</param>
    /// <returns>
    /// True when the key held <paramref name="expected"/> and this caller replaced it; false when it held nothing
    /// or another value.
    /// </returns>
    Task<bool> TryReplaceAsync<T>(
        string key, T expected, T value, StorageOptions options, CancellationToken? token = null);

    /// <summary>
    /// Gives the entry under <paramref name="key"/> a new expiration policy, keeping its value, when there is
    /// one, and reports whether there was.
    /// </summary>
    /// <remarks>
    /// Implementations must never write an entry the key does not hold when the call is decided: an entry that
    /// has expired or been removed stays gone, and an entry written by another caller keeps its value. This is
    /// what lets a record that others also write be kept longer without bringing back one that has already
    /// ended, or writing an old value over a newer one. A store that moves an expiry by itself, such as Redis
    /// with <c>EXPIRE</c>, gives this in one command; one that does not reads the value and writes it straight
    /// back, deciding between its own callers the way <see cref="TrySetIfAbsentAsync{T}"/> does.
    /// </remarks>
    /// <param name="key">The key whose entry is kept longer.</param>
    /// <param name="options">The new expiration policy.</param>
    /// <param name="token">An optional cancellation token.</param>
    /// <returns>True when the key held an entry and it now carries the new policy; false when it held none.
    /// </returns>
    Task<bool> TryExtendAsync(string key, StorageOptions options, CancellationToken? token = null);

    /// <summary>
    /// Removes the entity stored under <paramref name="key"/>; succeeds silently when no entry
    /// is present.
    /// </summary>
    /// <param name="key">The key of the entity to remove.</param>
    /// <param name="token">An optional cancellation token.</param>
    /// <returns>A task that completes once the removal request has been processed.</returns>
    Task RemoveAsync(string key, CancellationToken? token = null);
}
