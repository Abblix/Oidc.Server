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

using System.Text.Json;
using Abblix.SharedSignals.Transmitter;
using StackExchange.Redis;

namespace Abblix.SharedSignals.Redis;

/// <summary>
/// The outbox on Redis's own structures: a list carries each stream's order, a hash carries the
/// items, and every mutation is a server-side atomic operation - append, remove-by-value,
/// field delete - so concurrent transmitter REPLICAS compose instead of overwriting each other,
/// which is the hole a whole-queue-as-one-value implementation cannot close.
/// </summary>
/// <remarks>
/// The queue and item keys of one stream share a cluster hash tag, so they land on one slot and
/// the multi-key transactions here stay valid under Redis Cluster. Losing Redis loses pending
/// events - the tier is deliberate: the delivery protocols budget for dropped held events
/// (SSF 1.0 Section 8.1.2.1), so the queue belongs beside caches, not beside data that earns
/// backups.
/// </remarks>
/// <param name="connection">The Redis connection; opening and configuring it is the host's.</param>
public sealed class RedisEventOutbox(IConnectionMultiplexer connection) : IEventOutbox
{
    private const string KeyPrefix = $"{nameof(Abblix)}.{nameof(SharedSignals)}:{nameof(RedisEventOutbox)}:";

    private readonly IDatabase _database = connection.GetDatabase();

    /// <inheritdoc />
    public async Task EnqueueAsync(
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(streamId);
        ArgumentNullException.ThrowIfNull(item);

        // Order and payload land together or not at all: a jti listed without its item would
        // read as an acked ghost, an item without its listing would never be served.
        var transaction = _database.CreateTransaction();
        _ = transaction.ListRightPushAsync(QueueKeyOf(streamId), item.JwtId);
        _ = transaction.HashSetAsync(
            ItemsKeyOf(streamId), item.JwtId, JsonSerializer.SerializeToUtf8Bytes(item));

        await ExecuteAsync(transaction, streamId);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
    {
        if (maxCount is <= 0)
        {
            return [];
        }

        var listed = await _database.ListRangeAsync(
            QueueKeyOf(streamId), 0, maxCount is { } limit ? limit - 1 : -1);
        if (listed.Length == 0)
        {
            return [];
        }

        var stored = await _database.HashGetAsync(ItemsKeyOf(streamId), listed);

        var pending = new List<OutboxItem>(listed.Length);
        foreach (var value in stored)
        {
            // A listed jti whose item is gone was acknowledged between the two reads - the
            // remove-by-value has or will drop its listing too, so it is simply not pending.
            if (!value.IsNull)
            {
                pending.Add(JsonSerializer.Deserialize<OutboxItem>((byte[])value!)
                    ?? throw new InvalidOperationException(
                        $"An outbox item of stream '{streamId}' deserialized to null."));
            }
        }

        return pending;
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

        var transaction = _database.CreateTransaction();
        foreach (var jwtId in jwtIds)
        {
            _ = transaction.ListRemoveAsync(QueueKeyOf(streamId), jwtId);
            _ = transaction.HashDeleteAsync(ItemsKeyOf(streamId), jwtId);
        }

        await ExecuteAsync(transaction, streamId);
    }

    /// <inheritdoc />
    public async Task ClearAsync(string streamId, CancellationToken cancellationToken = default)
        => await _database.KeyDeleteAsync([QueueKeyOf(streamId), ItemsKeyOf(streamId)]);

    /// <summary>
    /// The stream identifier travels inside a cluster hash tag, which is what keeps both of a
    /// stream's keys on one slot - the ground the multi-key transactions stand on.
    /// </summary>
    private static RedisKey QueueKeyOf(string streamId) => $"{KeyPrefix}{{{streamId}}}:queue";

    private static RedisKey ItemsKeyOf(string streamId) => $"{KeyPrefix}{{{streamId}}}:items";

    private static async Task ExecuteAsync(ITransaction transaction, string streamId)
    {
        if (!await transaction.ExecuteAsync())
        {
            throw new InvalidOperationException(
                $"The outbox transaction of stream '{streamId}' did not execute; with no watched "
                + "keys that points at the connection, not at contention.");
        }
    }
}
