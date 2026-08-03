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

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The process-local outbox: right for a single-instance transmitter and for tests. Undelivered
/// events die with the process - a transmitter that owes durability registers a durable
/// implementation of <see cref="IEventOutbox"/> instead.
/// </summary>
public sealed class InMemoryEventOutbox : IEventOutbox
{
    private readonly ConcurrentDictionary<string, List<OutboxItem>> _queues = new();

    /// <inheritdoc />
    public ValueTask EnqueueAsync(
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(streamId);
        ArgumentNullException.ThrowIfNull(item);

        var queue = _queues.GetOrAdd(streamId, _ => []);
        lock (queue)
        {
            queue.Add(item);
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<OutboxItem>> PendingAsync(
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
    {
        if (!_queues.TryGetValue(streamId, out var queue))
        {
            return ValueTask.FromResult<IReadOnlyList<OutboxItem>>([]);
        }

        lock (queue)
        {
            IEnumerable<OutboxItem> head = queue;
            if (maxCount is { } limit)
            {
                head = head.Take(limit);
            }

            return ValueTask.FromResult<IReadOnlyList<OutboxItem>>(head.ToArray());
        }
    }

    /// <inheritdoc />
    public ValueTask AcknowledgeAsync(
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jwtIds);

        if (_queues.TryGetValue(streamId, out var queue) && jwtIds.Count > 0)
        {
            var acknowledged = new HashSet<string>(jwtIds, StringComparer.Ordinal);
            lock (queue)
            {
                queue.RemoveAll(item => acknowledged.Contains(item.JwtId));
            }
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask ClearAsync(string streamId, CancellationToken cancellationToken = default)
    {
        _queues.TryRemove(streamId, out _);
        return ValueTask.CompletedTask;
    }
}
