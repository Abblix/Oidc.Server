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

using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The outbox over the host's <see cref="IDistributedCache"/>: one entry per stream holding the
/// queue, so pending events survive a process restart when the store behind the cache does. The
/// tier is deliberate, and it is our decision rather than a permission the specification grants:
/// SSF 1.0 Section 8.1.2.1 lets a transmitter drop events held while a stream is PAUSED, and
/// requires transmission for an enabled one. Treating the whole queue as cache-tier follows the
/// delivery protocols' own tolerance for loss over a broken transport, and is why it belongs in
/// the cache tier rather than beside data that earns backups.
/// </summary>
/// <remarks>
/// <see cref="IDistributedCache"/> reads and writes whole values with no compare-and-set, so queue
/// mutations are serialized through an in-process gate per stream. That gate excludes this
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
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(streamId);
        ArgumentNullException.ThrowIfNull(item);

        var gate = GateOf(streamId);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var queue = await ReadQueueAsync(streamId, cancellationToken);
            queue.Add(item);
            await WriteQueueAsync(streamId, queue, cancellationToken);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
    {
        var queue = await ReadQueueAsync(streamId, cancellationToken);

        return maxCount is { } limit && queue.Count > limit
            ? queue.GetRange(0, limit)
            : queue;
    }

    /// <inheritdoc />
    public async Task AcknowledgeAsync(
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
        var gate = GateOf(streamId);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var queue = await ReadQueueAsync(streamId, cancellationToken);
            if (queue.RemoveAll(item => acknowledged.Contains(item.JwtId)) > 0)
            {
                await WriteQueueAsync(streamId, queue, cancellationToken);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task ClearAsync(string streamId, CancellationToken cancellationToken = default)
        => await cache.RemoveAsync(CacheKeyPrefix + streamId, cancellationToken);

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var gate in _gates.Values)
        {
            gate.Dispose();
        }
    }

    private SemaphoreSlim GateOf(string streamId)
        => _gates.GetOrAdd(streamId, _ => new SemaphoreSlim(1, 1));

    private async Task<List<OutboxItem>> ReadQueueAsync(string streamId, CancellationToken cancellationToken)
    {
        var stored = await cache.GetAsync(CacheKeyPrefix + streamId, cancellationToken);
        return stored is null
            ? []
            : JsonSerializer.Deserialize<List<OutboxItem>>(stored)
              ?? throw new InvalidOperationException(
                  $"The outbox entry of stream '{streamId}' deserialized to null.");
    }

    private async Task WriteQueueAsync(
        string streamId,
        List<OutboxItem> queue,
        CancellationToken cancellationToken)
    {
        var key = CacheKeyPrefix + streamId;
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
