// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using StackExchange.Redis;

namespace Abblix.Oidc.Server.Redis;

/// <summary>
/// Stores the server's short-lived entities in Redis, and takes a single-use one back in one
/// indivisible command, so exactly one caller redeems an authorization however many instances are
/// serving the token endpoint.
/// </summary>
/// <remarks>
/// This owns the whole record: the key it is stored under, the bytes it is stored as, and every read
/// of it. That is the point rather than an implementation detail. A component that only READS what
/// another one wrote cannot know either - a distributed cache promises bytes in and bytes out under a
/// logical key and promises nothing about what exists in the store behind it, so a command aimed at
/// that store finds something nobody described, or nothing at all.
/// <para>
/// <c>GETDEL</c> arrived in Redis 6.2. Where it is absent the same two lines run as a script, which
/// Redis executes with nothing interleaved, so both paths carry the same guarantee and the older one
/// costs a round trip's worth of script caching rather than correctness.
/// </para>
/// <para>
/// Which path applies is not asked of the server's version: a deployment can be a cluster of mixed
/// versions, and a version string answers for one node. The command is attempted, and the script
/// becomes this instance's path once it has been seen to TAKE a value where the command was refused.
/// Latching on the refusal alone would let one busy moment demote a server that knows the command for
/// the rest of the process's life, and the two cases cannot be told apart at the moment of the refusal:
/// the property naming the kind of error is published as experimental, so a shipped decision may not
/// rest on it.
/// </para>
/// </remarks>
/// <param name="connection">The Redis connection the host registers.</param>
/// <param name="serializer">Turns an entity into the bytes this stores, and back.</param>
/// <param name="timeProvider">Answers what time it is when a policy names an instant rather than a span.</param>
/// <param name="redisOptions">The key prefix and database this writes under.</param>
public sealed class RedisEntityStorage(
    IConnectionMultiplexer connection,
    IBinarySerializer serializer,
    TimeProvider timeProvider,
    RedisEntityStorageOptions redisOptions) : IEntityStorage
{
    /// <summary>
    /// The take, for a server without <c>GETDEL</c>. Redis runs a script with nothing interleaved,
    /// which is the whole reason this is equivalent rather than merely similar.
    /// </summary>
    private const string TakeScript =
        """
        local value = redis.call('GET', KEYS[1])
        if value then redis.call('DEL', KEYS[1]) end
        return value
        """;

    /// <summary>
    /// Set once the script has taken a value where the single command was refused.
    /// </summary>
    private volatile bool _useScript;

    private IDatabase Database => connection.GetDatabase(redisOptions.Database);

    private RedisKey KeyOf(string key) => redisOptions.KeyPrefix + key;

    /// <inheritdoc />
    public Task SetAsync<T>(string key, T value, StorageOptions options, CancellationToken? token = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(options);
        token?.ThrowIfCancellationRequested();

        // An entry with no expiry would outlive the authorization it stands for, and every caller in
        // the server states one. A key written without it is a leak the store cannot notice, so the
        // absence is refused here rather than turned into a default nobody chose.
        var expiry = ExpiryOf(options)
            ?? throw new ArgumentException(
                $"{nameof(StorageOptions)} carries no expiration, and this store writes no entry without one.",
                nameof(options));

        return Database.StringSetAsync(KeyOf(key), serializer.Serialize(value), expiry);
    }

    /// <inheritdoc />
    public async Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, CancellationToken? token = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        token?.ThrowIfCancellationRequested();

        var stored = removeOnRetrieval
            ? await TakeAsync(KeyOf(key))
            : await Database.StringGetAsync(KeyOf(key));

        return stored.IsNull ? default : serializer.Deserialize<T>((byte[])stored!);
    }

    /// <inheritdoc />
    public Task RemoveAsync(string key, CancellationToken? token = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        token?.ThrowIfCancellationRequested();

        return Database.KeyDeleteAsync(KeyOf(key));
    }

    /// <summary>
    /// Reads the value and deletes it with nothing able to run between the two.
    /// </summary>
    private async Task<RedisValue> TakeAsync(RedisKey key)
    {
        var database = Database;

        if (_useScript)
            return await TakeByScriptAsync(database, key);

        try
        {
            return await database.StringGetDeleteAsync(key);
        }
        catch (RedisServerException)
        {
            // A refusal is a command the server did not run, so nothing was taken and going on cannot
            // lose a value.
        }

        var taken = await TakeByScriptAsync(database, key);

        // Remembered only when the script actually took something, because that is what tells a server
        // LACKING the command from one that could not serve this call. An empty answer says neither.
        if (!taken.IsNull)
            _useScript = true;

        return taken;
    }

    private static async Task<RedisValue> TakeByScriptAsync(IDatabase database, RedisKey key)
    {
        var result = await database.ScriptEvaluateAsync(TakeScript, [key]);
        return result.IsNull ? RedisValue.Null : (RedisValue)result;
    }

    /// <summary>
    /// How long the entry has left, from whichever of the policy's instants the caller set.
    /// </summary>
    /// <remarks>
    /// Sliding expiration is not honored and cannot be: extending an authorization's life because
    /// somebody looked at it is what a polling client would use to keep a code alive forever. Nothing
    /// in the server sets it - the property is declared and forwarded and never assigned - so refusing
    /// it here costs no caller anything, and a host that starts setting it learns so at the write
    /// rather than by watching codes outlive their deadline.
    /// </remarks>
    private TimeSpan? ExpiryOf(StorageOptions options)
    {
        if (options.SlidingExpiration.HasValue)
        {
            throw new ArgumentException(
                $"{nameof(StorageOptions.SlidingExpiration)} would let a read extend an authorization, "
                + "which this store does not do.",
                nameof(options));
        }

        if (options.AbsoluteExpirationRelativeToNow.HasValue)
            return options.AbsoluteExpirationRelativeToNow;

        return options.AbsoluteExpiration.HasValue
            ? options.AbsoluteExpiration.Value - timeProvider.GetUtcNow()
            : null;
    }
}
