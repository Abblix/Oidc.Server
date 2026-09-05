// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The outbox over the host's <see cref="IDistributedCache"/>: one entry per stream holding the
/// queue, so pending events survive a process restart when the store behind the cache does. A
/// stream here is the receiver and the identifier together, as everywhere else. The
/// tier is deliberate, and it is our decision rather than a permission the specification grants:
/// SSF 1.0 Section 8.1.2.1 lets a transmitter drop events held while a stream is PAUSED, and
/// requires transmission for an enabled one. Treating the whole queue as cache-tier follows the
/// delivery protocols' own tolerance for loss over a broken transport, and is why it belongs in
/// the cache tier rather than beside data that earns backups.
/// </summary>
/// <remarks>
/// <see cref="IDistributedCache"/> reads and writes whole values with no compare-and-set, so queue
/// mutations are serialized through an in-process gate per stream, taken under the same composed
/// key the entry lives under - so the gate and the entry cannot disagree about which stream is
/// being guarded. That gate excludes this
/// instance's threads from each other and reaches no further, which makes this implementation
/// correct for a SINGLE transmitter instance and only that: two instances mutating one stream's
/// queue read the same value, each writes its own edit over the whole entry, and the later write
/// silently discards the earlier one's. No compare-and-set means the interface cannot express the
/// fix either - it is not a gap in this class. A transmitter running more than one instance takes
/// the outbox built on native list operations, <c>AddSharedSignalsRedisOutbox</c>.
/// </remarks>
/// <param name="cache">The distributed cache the queues live in; the store is the host's
/// choice.</param>
public sealed class DistributedCacheEventOutbox(IDistributedCache cache) : IEventOutbox, IDisposable
{
    /// <summary>
    /// Keeps the queues out of the way of whatever else shares the host's cache. Derived from
    /// the type's own name; entries orphaned by a rename are re-created empty, costing at most
    /// a redelivery the protocols already tolerate.
    /// </summary>
    private const string CacheKeyPrefix =
        $"{nameof(Abblix)}.{nameof(SharedSignals)}:{nameof(DistributedCacheEventOutbox)}:";

    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new();

    /// <inheritdoc />
    public async Task EnqueueAsync(
        string receiverId,
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(receiverId);
        ArgumentException.ThrowIfNullOrEmpty(streamId);
        ArgumentNullException.ThrowIfNull(item);

        var key = KeyOf(receiverId, streamId);
        var gate = GateOf(key);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var queue = await ReadQueueAsync(key, cancellationToken);
            queue.Add(item);
            await WriteQueueAsync(key, queue, cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string receiverId,
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
    {
        var queue = await ReadQueueAsync(KeyOf(receiverId, streamId), cancellationToken);

        return maxCount is { } limit && queue.Count > limit
            ? queue.GetRange(0, limit)
            : queue;
    }

    /// <inheritdoc />
    public async Task AcknowledgeAsync(
        string receiverId,
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jwtIds);

        if (jwtIds.Count == 0)
        {
            return;
        }

        var acknowledged = new HashSet<string>(jwtIds, StringComparer.Ordinal);
        var key = KeyOf(receiverId, streamId);
        var gate = GateOf(key);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var queue = await ReadQueueAsync(key, cancellationToken);
            if (queue.RemoveAll(item => acknowledged.Contains(item.JwtId)) > 0)
            {
                await WriteQueueAsync(key, queue, cancellationToken);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task ClearAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
        => await cache.RemoveAsync(KeyOf(receiverId, streamId), cancellationToken);

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var gate in _gates.Values)
        {
            gate.Dispose();
        }
    }

    /// <summary>
    /// The cache entry a stream's queue lives under, composed from the pair that identifies it.
    /// </summary>
    /// <remarks>
    /// Both halves are escaped before they are joined, so the separator cannot occur inside either
    /// and the join can only split where this expression put the separator. A plain concatenation
    /// cannot say that: a receiver named "a:b" with
    /// a stream "c" would address the same entry as a receiver "a" with a stream "b:c", and both
    /// halves are operator-chosen strings. That is the defect this key exists to close, arriving a
    /// second time through the key itself.
    /// </remarks>
    private static string KeyOf(string receiverId, string streamId)
        => CacheKeyPrefix + Uri.EscapeDataString(receiverId) + ":" + Uri.EscapeDataString(streamId);

    private SemaphoreSlim GateOf(string key)
        => _gates.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));

    private async Task<List<OutboxItem>> ReadQueueAsync(string key, CancellationToken cancellationToken)
    {
        var stored = await cache.GetAsync(key, cancellationToken);
        return stored is null
            ? []
            : JsonSerializer.Deserialize<List<OutboxItem>>(stored)
              ?? throw new InvalidOperationException(
                  $"The outbox entry at '{key}' deserialized to null.");
    }

    private async Task WriteQueueAsync(
        string key,
        List<OutboxItem> queue,
        CancellationToken cancellationToken)
    {
        if (queue.Count == 0)
        {
            // An empty queue is the same fact as no entry, and no entry keeps an abandoned
            // stream from parking bytes in the cache forever.
            await cache.RemoveAsync(key, cancellationToken);
            return;
        }

        await cache.SetAsync(key, JsonSerializer.SerializeToUtf8Bytes(queue), cancellationToken);
    }
}
