// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The process-local outbox: right for a single-instance transmitter and for tests. Undelivered
/// events die with the process - a transmitter that owes durability registers a durable
/// implementation of <see cref="IEventOutbox"/> instead.
/// </summary>
public sealed class InMemoryEventOutbox : IEventOutbox
{
    private readonly ConcurrentDictionary<(string ReceiverId, string StreamId), List<OutboxItem>>
        _queues = new();

    /// <inheritdoc />
    public Task EnqueueAsync(
        string receiverId,
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(receiverId);
        ArgumentException.ThrowIfNullOrEmpty(streamId);
        ArgumentNullException.ThrowIfNull(item);

        var key = (receiverId, streamId);

        // Re-checked under the lock, because a clear between the lookup and here removes the list
        // from the dictionary: adding to it then puts the event where nothing can read it, and this
        // method has no way to say so - it would report success into a queue that no longer exists.
        // The retry lands the event in whatever list is current, which is the right place for one
        // enqueued after a clear. It spins only while clears keep interleaving, and a clear is an
        // administrative act rather than traffic.
        while (true)
        {
            var queue = _queues.GetOrAdd(key, _ => []);
            lock (queue)
            {
                if (_queues.TryGetValue(key, out var current) && ReferenceEquals(current, queue))
                {
                    queue.Add(item);
                    break;
                }
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string receiverId,
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
    {
        if (!_queues.TryGetValue((receiverId, streamId), out var queue))
        {
            return Task.FromResult<IReadOnlyList<OutboxItem>>([]);
        }

        lock (queue)
        {
            IEnumerable<OutboxItem> head = queue;
            if (maxCount is { } limit)
            {
                head = head.Take(limit);
            }

            return Task.FromResult<IReadOnlyList<OutboxItem>>(head.ToArray());
        }
    }

    /// <inheritdoc />
    public Task AcknowledgeAsync(
        string receiverId,
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jwtIds);

        if (_queues.TryGetValue((receiverId, streamId), out var queue) && jwtIds.Count > 0)
        {
            var acknowledged = new HashSet<string>(jwtIds, StringComparer.Ordinal);
            lock (queue)
            {
                queue.RemoveAll(item => acknowledged.Contains(item.JwtId));
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task ClearAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
    {
        _queues.TryRemove((receiverId, streamId), out _);
        return Task.CompletedTask;
    }
}
