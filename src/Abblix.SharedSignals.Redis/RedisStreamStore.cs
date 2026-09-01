// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.SharedSignals.Transmitter;
using StackExchange.Redis;

namespace Abblix.SharedSignals.Redis;

/// <summary>
/// Stream registrations on one Redis hash: the durable <see cref="IStreamStore"/> for a transmitter
/// whose streams must outlive its process, without a database of its own.
/// </summary>
/// <remarks>
/// <para>One hash rather than a key per stream, because the dispatcher's view is "every stream at
/// once" on every event: HGETALL over a transmitter's registrations beats a SCAN walking a shared
/// keyspace, and a single key stays valid under Redis Cluster without hash-tag ceremony. The cost of
/// that shape is that the whole registry travels on every dispatched event and lives on one cluster
/// slot - fine for the tens of receivers a transmitter serves, and the reason this store is not the
/// answer for thousands.</para>
/// <para>The key carries the transmitter's own issuer, so two deployments sharing one Redis - a
/// staging and a production, two products - keep separate registries. Without it they would share a
/// hash, and each would read the other's streams out of <see cref="ListAllAsync"/> and deliver its own
/// signed events to the other's receivers.</para>
/// <para>Losing Redis loses registrations - deliberately a tier below a database. The consequence is
/// worth stating plainly: the transmitter stops delivering to everybody until each receiver creates
/// its stream again (SSF 1.0 Section 8.1.1.1), and whether a receiver ever does is a property of that
/// receiver, not of the protocol. A deployment that cannot accept that keeps its registrations in its
/// own database, which is what the interface is for.</para>
/// <para>Registrations carry the receivers' delivery credentials
/// (<c>authorization_header</c>), so this Redis holds secrets and deserves the protection of one:
/// TLS, authentication, and a database of its own.</para>
/// </remarks>
/// <param name="connection">The Redis connection; opening and configuring it is the host's.</param>
/// <param name="options">The transmitter's options, read for the issuer the key is scoped by.</param>
public sealed class RedisStreamStore(IConnectionMultiplexer connection, SharedSignalsTransmitterOptions options)
    : IStreamStore
{
    /// <summary>
    /// Enum members travel as their names. The default is the ordinal, which turns reordering a
    /// vocabulary - an edit with no wire consequence anywhere else - into a silent reinterpretation of
    /// every stored registration: <see cref="StreamSubjectsMode.All"/> would read back as
    /// <see cref="StreamSubjectsMode.None"/>, and a stream covering everyone would cover nobody.
    /// </summary>
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly RedisKey _hashKey =
        $"{nameof(Abblix)}.{nameof(SharedSignals)}:{nameof(RedisStreamStore)}:"
        + Uri.EscapeDataString(options.Issuer);

    private readonly IDatabase _database = connection.GetDatabase();

    /// <summary>
    /// The exact text a stored stream carries when its version is <paramref name="version"/>.
    /// </summary>
    /// <remarks>
    /// Compared as a substring of the stored document rather than by parsing it, so the script
    /// needs no JSON library and works on every server that speaks Lua. The property name and the
    /// quoting are what make the match exact: a version is a 32-character hex string, so the
    /// needle cannot occur anywhere else in the document. Nor can either needle be forged by
    /// anything a receiver supplies - a quote inside a JSON string value is escaped, so the raw
    /// sequence only ever appears where the serializer put it.
    /// </remarks>
    /// <param name="version">The version a caller believes is on record.</param>
    private static string VersionMarkerOf(string version) => $"{AnyVersionMarker}{version}\"";

    /// <summary>
    /// The text a stored stream carries when it has any version at all.
    /// </summary>
    /// <remarks>
    /// Its ABSENCE is what a caller holding no version is judged against. Versions arrived after this
    /// store had been shipping, so registrations written by the earlier build carry no such member,
    /// and a caller reading one is handed null - matching it against a version marker would refuse
    /// every write to that stream for as long as it exists, while telling the receiver it lost a race
    /// that never happened.
    /// </remarks>
    private const string AnyVersionMarker = "\"version\":\"";

    /// <summary>
    /// Joins receiver and stream into the hash field. Both parts are escaped before the separator
    /// joins them: the receiver id is whatever the host's authentication produced and may contain
    /// anything, and a composite key that trusts its inputs' alphabet is ambiguous the day one input
    /// widens - <c>("a|b", "c")</c> and <c>("a", "b|c")</c> address one field unescaped.
    /// </summary>
    private static RedisValue FieldOf(string receiverId, string streamId)
        => $"{Uri.EscapeDataString(receiverId)}|{Uri.EscapeDataString(streamId)}";

    /// <inheritdoc />
    public async Task<bool> TryCreateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        cancellationToken.ThrowIfCancellationRequested();

        // HSETNX: only the field's first writer wins, and Redis itself is the arbiter - a prior
        // existence check would lose the race a concurrent create of the same stream opens.
        return await _database.HashSetAsync(
            _hashKey,
            FieldOf(stream.ReceiverId, stream.StreamId),
            JsonSerializer.SerializeToUtf8Bytes(
                stream with { Version = Guid.NewGuid().ToString("N") }, SerializerOptions),
            When.NotExists);
    }

    /// <inheritdoc />
    public async Task<StreamState?> FindAsync(
        string receiverId, string streamId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var field = FieldOf(receiverId, streamId);
        var stored = await _database.HashGetAsync(_hashKey, field);

        // Unreadable is an error HERE, unlike in the listings below: the caller named this one stream,
        // so answering null would report it as absent and invite a create that then collides.
        return stored.IsNull ? null : Deserialize(stored, field);
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
        cancellationToken.ThrowIfCancellationRequested();

        var entries = await _database.HashGetAllAsync(_hashKey);

        // An unreadable entry is skipped rather than thrown, and the asymmetry with FindAsync is the
        // point. This list is the dispatcher's view of who to deliver to, read on EVERY event: one
        // entry a newer or older version wrote in a shape this one cannot parse would otherwise stop
        // every signal to every receiver. Losing one registration is the smaller failure, and it is
        // the one confined to whoever owns the broken entry.
        var streams = new List<StreamState>(entries.Length);
        foreach (var entry in entries)
        {
            if (TryDeserialize(entry.Value, out var stream))
                streams.Add(stream);
        }

        return streams;
    }

    /// <inheritdoc />
    public async Task<bool> UpdateAsync(StreamState stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        cancellationToken.ThrowIfCancellationRequested();

        // Replace-if-exists as one server-side script, and the script is what makes the answer mean
        // what the interface says. The obvious alternative - a transaction conditioned on the field
        // existing - watches the KEY, and this store keeps every stream under one key: a write by any
        // other connection between the watch and the commit aborts it, and the abort is
        // indistinguishable from "no such stream". The management service turns that into a 404 while
        // the update is silently lost, and it happens exactly under the load this package exists for,
        // a transmitter running more than one replica. Measured: unnoticeable from a single
        // multiplexer, the majority of updates from two.
        // The version is compared server-side, in the same script that writes: a caller may only
        // replace the copy it read. Reading it here and comparing in C# would be the very
        // read-modify-write this is meant to close.
        // A caller whose copy carried no version replaces one that still carries none, and gains a
        // version by doing so - the migration for registrations written before versions existed, and
        // one that happens per stream on its first change rather than as a pass over the store. The
        // condition runs in the same place and the same direction for both: any version on record
        // means somebody has written since that read, which is the lost update this exists to refuse.
        // Which needle, and which way it has to come out: one decision, because the two are one
        // fact. Derived separately they disagree the day either is edited, and disagreeing means
        // looking for a version marker while requiring it to be missing, which refuses every write.
        var (needle, mustBeFound) = stream.Version is { } version
            ? (VersionMarkerOf(version), "1")
            : (AnyVersionMarker, "0");

        var replaced = await _database.ScriptEvaluateAsync(
            """
            local stored = redis.call('HGET', KEYS[1], ARGV[1])
            if not stored then
                return 0
            end
            local present = string.find(stored, ARGV[3], 1, true) ~= nil
            if present ~= (ARGV[4] == '1') then
                return 0
            end
            redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
            return 1
            """,
            [_hashKey],
            [FieldOf(stream.ReceiverId, stream.StreamId),
             (RedisValue)JsonSerializer.SerializeToUtf8Bytes(
                 stream with { Version = Guid.NewGuid().ToString("N") }, SerializerOptions),
             (RedisValue)needle,
             (RedisValue)mustBeFound]);

        return (long)replaced == 1;
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(
        string receiverId, string streamId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _database.HashDeleteAsync(_hashKey, FieldOf(receiverId, streamId));
    }

    private static StreamState Deserialize(RedisValue stored, RedisValue field)
        => TryDeserialize(stored, out var stream)
            ? stream
            : throw new InvalidOperationException(
                $"The stored stream registration '{field}' could not be read.");

    private static bool TryDeserialize(RedisValue stored, out StreamState stream)
    {
        try
        {
            var read = JsonSerializer.Deserialize<StreamState>((byte[])stored!, SerializerOptions);
            stream = read!;
            return read is not null;
        }
        catch (JsonException)
        {
            stream = null!;
            return false;
        }
    }
}
