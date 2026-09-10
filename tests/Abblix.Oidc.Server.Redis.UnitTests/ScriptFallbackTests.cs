// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Redis;
using Abblix.Tests.Shared;
using Moq;
using StackExchange.Redis;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// The path a server older than Redis 6.2 takes, driven against a REAL server that has been made to
/// refuse the single command.
/// </summary>
/// <remarks>
/// Every server this suite can start knows <c>GETDEL</c>, so without something in the way the script, the
/// latch and the Lua text all ship unexecuted - and the deployments they exist for are exactly the ones
/// nobody will be watching. So the refusal is staged and everything else, the script included, goes to
/// the same Garnet the other rows use: what is faked is the one command, not the take.
/// </remarks>
public sealed class ScriptFallbackTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly StorageOptions OneMinute =
        new() { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1) };

    private sealed record Stored(string Value);

    /// <summary>
    /// How many times the single command was attempted, so the latch can be observed rather than assumed.
    /// </summary>
    private int _refusals;

    /// <summary>
    /// A connection whose <c>GETDEL</c> is refused the way a server that does not know it refuses, and
    /// whose every other command is the real one.
    /// </summary>
    private IConnectionMultiplexer RefusingTheSingleCommand()
    {
        var real = garnet.Connection.GetDatabase();

        var database = new Mock<IDatabase>(MockBehavior.Strict);

        database
            .Setup(db => db.StringGetDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Returns(() =>
            {
                Interlocked.Increment(ref _refusals);
#pragma warning disable CS0618
                // The constructor naming the kind of error is published as experimental, so it may not be
                // built into the suite that pins a shipped decision.
                throw new RedisServerException("ERR unknown command 'GETDEL'");
#pragma warning restore CS0618
            });

        database
            .Setup(db => db.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>(),
                It.IsAny<CommandFlags>()))
            .Returns((string script, RedisKey[] keys, RedisValue[] values, CommandFlags flags)
                => real.ScriptEvaluateAsync(script, keys, values, flags));

        // The four-argument overload, because that is the one the storage calls: naming the flags as well
        // sets up a method nothing invokes, and a strict mock then fails on the call that was made.
        database
            .Setup(db => db.StringSetAsync(
                It.IsAny<RedisKey>(),
                It.IsAny<RedisValue>(),
                It.IsAny<TimeSpan?>(),
                It.IsAny<When>()))
            .Returns((RedisKey key, RedisValue value, TimeSpan? expiry, When when)
                => real.StringSetAsync(key, value, expiry, when));

        database
            .Setup(db => db.StringGetAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .Returns((RedisKey key, CommandFlags flags) => real.StringGetAsync(key, flags));

        var connection = new Mock<IConnectionMultiplexer>(MockBehavior.Strict);
        connection.Setup(c => c.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(database.Object);
        return connection.Object;
    }

    private RedisEntityStorage NewStorage() => new(
        RefusingTheSingleCommand(),
        new JsonBinarySerializer(),
        TimeProvider.System,
        new RedisEntityStorageOptions { KeyPrefix = $"fallback:{Guid.NewGuid():N}:" });

    [Fact]
    public async Task AServerRefusingTheSingleCommand_StillTakesTheValueExactlyOnce()
    {
        var storage = NewStorage();
        var key = $"entity:{Guid.NewGuid():N}";

        await storage.SetAsync(key, new Stored("an-authorization"), OneMinute, Ct);

        Assert.Equal(new Stored("an-authorization"), await storage.GetAsync<Stored>(key, true, Ct));
        Assert.Null(await storage.GetAsync<Stored>(key, true, Ct));
    }

    /// <summary>
    /// The refusal is paid for once: after the script has taken a value, the single command is not tried
    /// again on this instance.
    /// </summary>
    [Fact]
    public async Task OnceTheScriptHasTaken_TheSingleCommandIsNotAttemptedAgain()
    {
        var storage = NewStorage();
        var first = $"entity:{Guid.NewGuid():N}";
        var second = $"entity:{Guid.NewGuid():N}";

        await storage.SetAsync(first, new Stored("first"), OneMinute, Ct);
        await storage.SetAsync(second, new Stored("second"), OneMinute, Ct);

        Assert.Equal(new Stored("first"), await storage.GetAsync<Stored>(first, true, Ct));
        Assert.Equal(new Stored("second"), await storage.GetAsync<Stored>(second, true, Ct));

        Assert.Equal(1, _refusals);
    }

    /// <summary>
    /// A refusal the script cannot answer either leaves the single command in use, because what tells a
    /// server LACKING the command from one that could not serve this call is whether the script took.
    /// </summary>
    [Fact]
    public async Task WhenTheScriptTakesNothing_TheSingleCommandStaysInUse()
    {
        var storage = NewStorage();
        var missing = $"entity:{Guid.NewGuid():N}";
        var present = $"entity:{Guid.NewGuid():N}";

        await storage.SetAsync(present, new Stored("an-authorization"), OneMinute, Ct);

        // Nothing there, so the script answers empty and settles nothing about the server.
        Assert.Null(await storage.GetAsync<Stored>(missing, true, Ct));

        // Which is why the next take tries the single command again rather than assuming it is absent.
        Assert.Equal(new Stored("an-authorization"), await storage.GetAsync<Stored>(present, true, Ct));

        Assert.Equal(2, _refusals);
    }
}
