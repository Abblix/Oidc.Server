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
    public Task EnqueueAsync(
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(streamId);
        ArgumentNullException.ThrowIfNull(item);

        // Re-checked under the lock, because a clear between the lookup and here removes the list
        // from the dictionary: adding to it then puts the event where nothing can read it, and this
        // method has no way to say so - it would report success into a queue that no longer exists.
        // The retry lands the event in whatever list is current, which is the right place for one
        // enqueued after a clear. It spins only while clears keep interleaving, and a clear is an
        // administrative act rather than traffic.
        while (true)
        {
            var queue = _queues.GetOrAdd(streamId, _ => []);
            lock (queue)
            {
                if (_queues.TryGetValue(streamId, out var current) && ReferenceEquals(current, queue))
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
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
    {
        if (!_queues.TryGetValue(streamId, out var queue))
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

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task ClearAsync(string streamId, CancellationToken cancellationToken = default)
    {
        _queues.TryRemove(streamId, out _);
        return Task.CompletedTask;
    }
}
