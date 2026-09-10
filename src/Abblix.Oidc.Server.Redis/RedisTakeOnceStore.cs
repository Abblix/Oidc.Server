// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Storages;
using StackExchange.Redis;

namespace Abblix.Oidc.Server.Redis;

/// <summary>
/// Takes a stored authorization and deletes it in one Redis command, so exactly one caller redeems it
/// however many instances are serving the token endpoint.
/// </summary>
/// <remarks>
/// <c>GETDEL</c> arrived in Redis 6.2. Where it is absent the same two lines run as a script, which Redis
/// executes atomically, so both paths give the same guarantee and the older one costs a round trip's worth
/// of script caching rather than correctness.
/// <para>
/// Which path applies is not asked of the server's version: a deployment can be a cluster of mixed
/// versions, and a version string is a claim about one node. The command is attempted, and the script
/// becomes this instance's path once it has been seen to answer where the command was refused.
/// </para>
/// </remarks>
/// <param name="connection">The Redis connection the server's other Redis-backed features share.</param>
public sealed class RedisTakeOnceStore(IConnectionMultiplexer connection) : ITakeOnceStore
{
    /// <summary>
    /// The same take, for a server without <c>GETDEL</c>. Redis runs a script with nothing interleaved,
    /// which is the whole reason this is equivalent rather than merely similar.
    /// </summary>
    private const string TakeScript =
        """
        local value = redis.call('GET', KEYS[1])
        if value then redis.call('DEL', KEYS[1]) end
        return value
        """;

    /// <summary>
    /// Set once the script has taken where the single command was refused, so the refusal is paid for
    /// one time rather than on every take.
    /// </summary>
    private volatile bool _useScript;

    /// <summary>
    /// Starts on the script path, so the older servers' path can be driven against a real server instead
    /// of being reasoned about.
    /// </summary>
    /// <remarks>
    /// Every server the suite can start knows <c>GETDEL</c>, so without this seam the script is code that
    /// ships and never runs here, and the claim that both paths take a value once would rest on reading.
    /// </remarks>
    /// <param name="connection">The Redis connection to take through.</param>
    /// <param name="useScript">Whether to skip the single command and go straight to the script.</param>
    internal RedisTakeOnceStore(IConnectionMultiplexer connection, bool useScript)
        : this(connection)
    {
        _useScript = useScript;
    }

    /// <inheritdoc />
    public async Task<byte[]?> TryTakeAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        cancellationToken.ThrowIfCancellationRequested();

        var database = connection.GetDatabase();

        if (_useScript)
            return await TakeByScriptAsync(database, key);

        try
        {
            return await database.StringGetDeleteAsync(key);
        }
        catch (RedisServerException)
        {
            // A refusal is a command the server did not run, so nothing was taken and retrying cannot
            // lose a value. Which refusal it was cannot be asked here: the property naming the kind is
            // published as experimental, and a shipped decision may not rest on one.
        }

        var taken = await TakeByScriptAsync(database, key);

        // Remembered only now, because the script ANSWERING is what distinguishes a server that lacks
        // the command from one that was momentarily unable to serve it. Latching on the refusal itself
        // would let one busy moment send every later take down the slower path for the process's life.
        _useScript = true;
        return taken;
    }

    private static async Task<byte[]?> TakeByScriptAsync(IDatabase database, string key)
    {
        var result = await database.ScriptEvaluateAsync(TakeScript, [key]);
        return result.IsNull ? null : (byte[]?)result;
    }
}
