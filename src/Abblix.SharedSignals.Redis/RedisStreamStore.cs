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
/// Stream registrations on one Redis hash: the durable <see cref="IStreamStore"/> for a transmitter
/// whose streams must outlive its process, without a database of its own.
/// </summary>
/// <remarks>
/// One hash rather than a key per stream, because the dispatcher's view is "every stream at once" on
/// every event: HGETALL over a transmitter's handful of registrations beats a SCAN walking a shared
/// keyspace, and a single key stays valid under Redis Cluster without hash-tag ceremony. Losing Redis
/// loses registrations - a tier above the outbox's, deliberately below a database's: a receiver
/// re-asserts its stream on its own schedule (SSF 1.0 Section 7 makes discovery and re-registration
/// cheap), and the window without one is priced by the receiver's cache TTL. A deployment that cannot
/// accept that window keeps its registrations in its own database instead.
/// </remarks>
/// <param name="connection">The Redis connection; opening and configuring it is the host's.</param>
public sealed class RedisStreamStore(IConnectionMultiplexer connection) : IStreamStore
{
    private static readonly RedisKey HashKey =
        $"{nameof(Abblix)}.{nameof(SharedSignals)}:{nameof(RedisStreamStore)}";

    private readonly IDatabase _database = connection.GetDatabase();

    /// <summary>
    /// Joins receiver and stream into the hash field. Both parts are escaped before the separator
    /// joins them: the receiver id is whatever the host's authentication produced and may contain
    /// anything, and a composite key that trusts its inputs' alphabet is ambiguous the day one input
    /// widens.
    /// </summary>
    private static RedisValue FieldOf(string receiverId, string streamId)
        => $"{Uri.EscapeDataString(receiverId)}|{Uri.EscapeDataString(streamId)}";

    /// <inheritdoc />
    public async Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        // HSETNX: only the field's first writer wins, and Redis itself is the arbiter - a prior
        // existence check would lose the race a concurrent create of the same stream opens.
        return await _database.HashSetAsync(
            HashKey,
            FieldOf(stream.ReceiverId, stream.StreamId),
            JsonSerializer.SerializeToUtf8Bytes(stream),
            When.NotExists);
    }

    /// <inheritdoc />
    public async Task<StreamState?> FindAsync(
        string receiverId, string streamId, CancellationToken cancellationToken = default)
    {
        var stored = await _database.HashGetAsync(HashKey, FieldOf(receiverId, streamId));
        return stored.IsNull ? null : Deserialize(stored);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<StreamState>> ListAsync(
        string receiverId, CancellationToken cancellationToken = default)
        => (await ListAllAsync(cancellationToken))
            .Where(stream => string.Equals(stream.ReceiverId, receiverId, StringComparison.Ordinal))
            .ToArray();

    /// <inheritdoc />
    public async Task<IReadOnlyList<StreamState>> ListAllAsync(CancellationToken cancellationToken = default)
    {
        var entries = await _database.HashGetAllAsync(HashKey);
        return entries.Select(entry => Deserialize(entry.Value)).ToArray();
    }

    /// <inheritdoc />
    public async Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        // Replace-if-exists as one conditioned transaction: Update must refuse a stream nobody
        // created, and a separate exists-then-set would let a concurrent delete be silently undone by
        // the set that lost the race. No Lua on purpose - MULTI/EXEC with a watched condition is the
        // portable form, and the wire-compatible servers the tests run on speak it natively.
        var transaction = _database.CreateTransaction();
        transaction.AddCondition(Condition.HashExists(HashKey, FieldOf(stream.ReceiverId, stream.StreamId)));
        _ = transaction.HashSetAsync(
            HashKey,
            FieldOf(stream.ReceiverId, stream.StreamId),
            JsonSerializer.SerializeToUtf8Bytes(stream));

        return await transaction.ExecuteAsync();
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(
        string receiverId, string streamId, CancellationToken cancellationToken = default)
        => await _database.HashDeleteAsync(HashKey, FieldOf(receiverId, streamId));

    private static StreamState Deserialize(RedisValue stored)
        => JsonSerializer.Deserialize<StreamState>((byte[])stored!)
           ?? throw new InvalidOperationException("A stored stream registration deserialized to null.");
}
