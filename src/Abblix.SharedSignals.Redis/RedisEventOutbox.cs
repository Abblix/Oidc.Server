// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.SharedSignals.Transmitter;
using StackExchange.Redis;

namespace Abblix.SharedSignals.Redis;

/// <summary>
/// The outbox on Redis's own structures: a list carries each stream's order, a hash carries the
/// items, and every mutation is a server-side operation - append, remove-by-value, field delete - so
/// concurrent transmitter REPLICAS compose instead of overwriting each other, which is the hole a
/// whole-queue-as-one-value implementation cannot close.
/// </summary>
/// <remarks>
/// <para>The mutations run as server-side scripts rather than MULTI/EXEC, and the difference is what
/// the caller is told. Redis has no rollback in either form: a command that fails at execution time
/// does not undo its predecessors. But a transaction reports that failure only inside the EXEC reply,
/// which a caller discarding the per-command tasks never reads - so a half-applied enqueue returned
/// success, and the signed event sat in the hash unreachable forever. A script's error reaches the
/// caller instead. What remains possible is a partial write, so the order is chosen to make the
/// survivor harmless: the payload is stored first and listed second, because a payload nobody listed
/// is invisible and expires, while a listing whose payload never arrived would be served forever and
/// never acknowledged.</para>
/// <para>The queue and item keys of one stream share a cluster hash tag, so they land on one slot and
/// the multi-key scripts here stay valid under Redis Cluster.</para>
/// <para>Losing Redis loses pending events, and the tier is deliberate. SSF 1.0 Section 8.1.2.1 lets a
/// transmitter drop events it holds while a stream is PAUSED; for an enabled stream the same section
/// requires transmission, so treating the whole queue as cache-tier is our decision rather than a
/// permission the specification grants. It follows the delivery protocols' own tolerance for
/// redelivery and loss over a broken transport, and it is why the queue belongs beside caches rather
/// than beside data that earns backups.</para>
/// </remarks>
/// <param name="connection">The Redis connection; opening and configuring it is the host's.</param>
/// <param name="options">What the queue may keep, and for how long.</param>
public sealed class RedisEventOutbox(IConnectionMultiplexer connection, RedisOutboxOptions options)
    : IEventOutbox
{
    private const string KeyPrefix = $"{nameof(Abblix)}.{nameof(SharedSignals)}:{nameof(RedisEventOutbox)}:";

    /// <summary>
    /// Enum members would travel as names rather than ordinals. There is no enum in
    /// <see cref="OutboxItem"/> today; the options are here so the day one arrives it does not silently
    /// store a number whose meaning changes when the vocabulary is reordered.
    /// </summary>
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>
    /// Stores the payload, lists it if it is new, and refreshes both keys' expiry.
    /// </summary>
    /// <remarks>
    /// HSET precedes RPUSH deliberately (see the class remarks), and the existence check is what makes
    /// a repeated identifier idempotent rather than destructive: a plain append would list the same
    /// identifier twice while the hash kept one payload, so one event would be delivered twice and
    /// another lost.
    /// </remarks>
    private const string EnqueueScript =
        """
        local isNew = redis.call('HEXISTS', KEYS[2], ARGV[1]) == 0
        redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
        if isNew then
            redis.call('RPUSH', KEYS[1], ARGV[1])
        end
        redis.call('PEXPIRE', KEYS[1], ARGV[3])
        redis.call('PEXPIRE', KEYS[2], ARGV[3])
        return 1
        """;

    /// <summary>Drops each identifier's listing and payload.</summary>
    /// <remarks>
    /// The listing goes first: a payload outliving its listing is invisible and expires, while a
    /// listing outliving its payload would be served on every pass and never acknowledged.
    /// </remarks>
    private const string AcknowledgeScript =
        """
        for index = 1, #ARGV do
            redis.call('LREM', KEYS[1], 0, ARGV[index])
            redis.call('HDEL', KEYS[2], ARGV[index])
        end
        return 1
        """;

    private readonly IDatabase _database = connection.GetDatabase();

    /// <inheritdoc />
    public async Task EnqueueAsync(
        string receiverId,
        string streamId,
        OutboxItem item,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentException.ThrowIfNullOrEmpty(item.JwtId);
        cancellationToken.ThrowIfCancellationRequested();

        await _database.ScriptEvaluateAsync(
            EnqueueScript,
            [QueueKeyOf(receiverId, streamId), ItemsKeyOf(receiverId, streamId)],
            [
                item.JwtId,
                JsonSerializer.SerializeToUtf8Bytes(item, SerializerOptions),
                (long)options.Retention.TotalMilliseconds,
            ]);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<OutboxItem>> PendingAsync(
        string receiverId,
        string streamId,
        int? maxCount = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (maxCount is <= 0)
        {
            return [];
        }

        var listed = await _database.ListRangeAsync(
            QueueKeyOf(receiverId, streamId), 0, maxCount is { } limit ? limit - 1 : -1);
        if (listed.Length == 0)
        {
            return [];
        }

        var stored = await _database.HashGetAsync(ItemsKeyOf(receiverId, streamId), listed);

        var pending = new List<OutboxItem>(listed.Length);
        var unreadable = new List<RedisValue>();
        for (var index = 0; index < stored.Length; index++)
        {
            var value = stored[index];

            // A listed jti whose item is gone was acknowledged between the two reads - the
            // remove-by-value has or will drop its listing too, so it is simply not pending.
            if (value.IsNull)
            {
                continue;
            }

            if (TryDeserialize(value, out var item))
            {
                pending.Add(item);
            }
            else
            {
                // Unreadable is skipped rather than thrown, and its listing is dropped below. Throwing
                // here would wedge the stream permanently: this read is the delivery pass, nothing else
                // removes an item, and acknowledgement only ever names an identifier a consumer read.
                // One entry a newer or older version wrote in a shape this one cannot parse would
                // otherwise stop every event to this receiver, forever.
                unreadable.Add(listed[index]);
            }
        }

        if (unreadable.Count > 0)
        {
            await AcknowledgeAsync(
                receiverId, streamId, [.. unreadable.Select(value => value.ToString())], cancellationToken);
        }

        return pending;
    }

    /// <inheritdoc />
    public async Task AcknowledgeAsync(
        string receiverId,
        string streamId,
        IReadOnlyCollection<string> jwtIds,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(jwtIds);
        cancellationToken.ThrowIfCancellationRequested();

        if (jwtIds.Count == 0)
        {
            return;
        }

        await _database.ScriptEvaluateAsync(
            AcknowledgeScript,
            [QueueKeyOf(receiverId, streamId), ItemsKeyOf(receiverId, streamId)],
            [.. jwtIds.Select(jwtId => (RedisValue)jwtId)]);
    }

    /// <inheritdoc />
    public async Task ClearAsync(
        string receiverId,
        string streamId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _database.KeyDeleteAsync(
            [QueueKeyOf(receiverId, streamId), ItemsKeyOf(receiverId, streamId)]);
    }

    /// <summary>
    /// The stream's identity travels inside a cluster hash tag, which is what keeps both of a
    /// stream's keys on one slot - the ground the multi-key scripts stand on.
    /// </summary>
    /// <remarks>
    /// The identity is the receiver and the identifier together, and both halves are escaped before
    /// they are joined. Three separate things hold here and it is worth keeping them apart, because
    /// the guard this replaced was justified by the wrong one of them.
    /// <list type="bullet">
    ///   <item><strong>The ESCAPING is what closes CROSSSLOT.</strong> Redis reads the tag as the text
    ///   between the first <c>{</c> and the first <c>}</c> after it; an empty tag does not apply and the
    ///   whole key is hashed instead, which puts a stream's two keys on two slots because they differ by
    ///   suffix. Only <c>}</c> does anything: an opening brace is ordinary text inside a tag. And its
    ///   two positions cost different things, of which one costs correctness - a <c>}</c> at the very
    ///   START of the tag, which means leading the receiver, leaves the tag empty and sends the two keys
    ///   to different slots, while one anywhere else merely cuts the tag short, and both keys are cut
    ///   identically so they stay together. The second is about how streams spread over the cluster; the
    ///   first breaks every multi-key script for that receiver. Neither identifier is ours to trust: a
    ///   receiver id is a <c>sub</c> claim or the host's configuration, and nothing anywhere refuses one
    ///   opening with <c>}</c>.</item>
    ///   <item><strong>The escaping also decides where the join splits</strong>, since it emits no
    ///   <c>:</c> either: the separator can only be the one this expression put there, so a receiver
    ///   named "a:b" with a stream "c" cannot address the queue of a receiver "a" with a stream "b:c" -
    ///   this defect arriving a second time through the key. Not quite one-to-one, which would be a
    ///   wider claim than holds: an unpaired surrogate escapes to the replacement character's bytes, so
    ///   two receivers differing only in one of those share a queue.</item>
    ///   <item><strong>The empty-half refusal is ordinary argument checking</strong> and carries no
    ///   consequence beyond itself: an identifier with nothing in it is not an identifier. It is worth
    ///   saying because the first version of this remark justified it with a collision the escaping
    ///   already makes impossible, and a guard defended by a false reason is a guard somebody deletes.
    ///   </item>
    /// </list>
    /// </remarks>
    private static RedisKey QueueKeyOf(string receiverId, string streamId)
        => KeyOf(receiverId, streamId, "queue");

    private static RedisKey ItemsKeyOf(string receiverId, string streamId)
        => KeyOf(receiverId, streamId, "items");

    private static RedisKey KeyOf(string receiverId, string streamId, string suffix)
    {
        ArgumentException.ThrowIfNullOrEmpty(receiverId);
        ArgumentException.ThrowIfNullOrEmpty(streamId);

        var tag = $"{Uri.EscapeDataString(receiverId)}:{Uri.EscapeDataString(streamId)}";
        return $"{KeyPrefix}{{{tag}}}:{suffix}";
    }

    private static bool TryDeserialize(RedisValue stored, out OutboxItem item)
    {
        try
        {
            var read = JsonSerializer.Deserialize<OutboxItem>((byte[])stored!, SerializerOptions);

            // A payload that parses but carries no identifier is unreadable too, and worse than
            // unparseable: it would be served and could never be acknowledged, because acknowledgement
            // addresses items by that very identifier.
            item = read!;
            return read is not null && !string.IsNullOrEmpty(read.JwtId);
        }
        catch (JsonException)
        {
            item = null!;
            return false;
        }
    }
}
