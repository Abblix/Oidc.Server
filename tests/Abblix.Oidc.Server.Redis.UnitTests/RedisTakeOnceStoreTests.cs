// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text;
using Abblix.Oidc.Server.Redis;
using Abblix.Tests.Shared;
using Moq;
using StackExchange.Redis;
using Xunit;

namespace Abblix.Oidc.Server.Redis.UnitTests;

/// <summary>
/// Pins the take against a REAL Redis-protocol server, the embedded Garnet the shared fixture starts.
/// </summary>
/// <remarks>
/// A fake would answer whatever this test taught it, and the whole claim here is about what the SERVER
/// does when two callers arrive together. Only a server that actually serializes commands can settle it.
/// </remarks>
public sealed class RedisTakeOnceStoreTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private RedisTakeOnceStore NewStore() => new(garnet.Connection);

    private static string NewKey() => $"take-once:{Guid.NewGuid():N}";

    /// <summary>
    /// The refusal a server without the single command answers with.
    /// </summary>
    /// <remarks>
    /// The constructor taking the error kind is published as experimental, so it may not be built into
    /// anything that ships nor into the suite pinning it; this is the form that stays.
    /// </remarks>
    private static RedisServerException UnknownCommand() =>
#pragma warning disable CS0618
        new("ERR unknown command 'GETDEL'");
#pragma warning restore CS0618

    private async Task<string> StoredAsync(string value)
    {
        var key = NewKey();
        await garnet.Connection.GetDatabase().StringSetAsync(key, value);
        return key;
    }

    [Fact]
    public async Task TryTakeAsync_AStoredValue_ComesBackAndIsGone()
    {
        var key = await StoredAsync("an-authorization");

        var taken = await NewStore().TryTakeAsync(key, Ct);

        Assert.NotNull(taken);
        Assert.Equal("an-authorization", Encoding.UTF8.GetString(taken));
        Assert.False(await garnet.Connection.GetDatabase().KeyExistsAsync(key));
    }

    [Fact]
    public async Task TryTakeAsync_AKeyHoldingNothing_AnswersNull()
    {
        Assert.Null(await NewStore().TryTakeAsync(NewKey(), Ct));
    }

    [Fact]
    public async Task TryTakeAsync_TwiceOverOneValue_AnswersTheSecondCallerNothing()
    {
        var key = await StoredAsync("an-authorization");
        var store = NewStore();

        Assert.NotNull(await store.TryTakeAsync(key, Ct));
        Assert.Null(await store.TryTakeAsync(key, Ct));
    }

    /// <summary>
    /// The claim this package exists for: many callers, one winner, and the value never destroyed with
    /// nobody told it won.
    /// </summary>
    /// <remarks>
    /// Driven against the server rather than reasoned about, and repeated over many keys, because a race
    /// that resolves correctly once may only have failed to interleave.
    /// </remarks>
    [Fact]
    public async Task TryTakeAsync_ManyCallersAtOnce_HandsTheValueToExactlyOne()
    {
        const int keys = 50;
        const int callersPerKey = 8;

        var store = NewStore();

        for (var i = 0; i < keys; i++)
        {
            var key = await StoredAsync($"authorization-{i}");

            var takes = Enumerable
                .Range(0, callersPerKey)
                .Select(_ => Task.Run(() => store.TryTakeAsync(key, Ct), Ct))
                .ToArray();

            var results = await Task.WhenAll(takes);

            Assert.Equal(1, results.Count(value => value is not null));
        }
    }

    /// <summary>
    /// The same claim on the path an older server takes, driven against the real server rather than read.
    /// </summary>
    /// <remarks>
    /// Every server this suite can start knows the single command, so the script would otherwise be code
    /// that ships and never runs here.
    /// </remarks>
    [Fact]
    public async Task TryTakeAsync_OnTheScriptPath_StillHandsTheValueToExactlyOne()
    {
        const int callers = 8;

        var store = new RedisTakeOnceStore(garnet.Connection, useScript: true);
        var key = await StoredAsync("an-authorization");

        var takes = Enumerable
            .Range(0, callers)
            .Select(_ => Task.Run(() => store.TryTakeAsync(key, Ct), Ct))
            .ToArray();

        var results = await Task.WhenAll(takes);

        Assert.Equal(1, results.Count(value => value is not null));
        Assert.Equal("an-authorization", Encoding.UTF8.GetString(results.Single(value => value is not null)!));
        Assert.Null(await store.TryTakeAsync(key, Ct));
    }

    /// <summary>
    /// A server that does not know the single command must not cost the caller the value: the refusal
    /// means nothing was taken, so the script has to run and answer.
    /// </summary>
    /// <remarks>
    /// Driven through a stand-in rather than a server, because no server available here refuses the
    /// command, and the branch that matters is what this code does with the refusal.
    /// </remarks>
    [Fact]
    public async Task TryTakeAsync_AServerRefusingTheSingleCommand_TakesThroughTheScript()
    {
        var database = new Mock<IDatabase>();
        database
            .Setup(db => db.StringGetDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(UnknownCommand());
        database
            .Setup(db => db.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>(),
                It.IsAny<CommandFlags>()))
            .ReturnsAsync(RedisResult.Create((RedisValue)"an-authorization"));

        var connection = new Mock<IConnectionMultiplexer>();
        connection.Setup(c => c.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(database.Object);

        var store = new RedisTakeOnceStore(connection.Object);

        Assert.Equal("an-authorization", Encoding.UTF8.GetString((await store.TryTakeAsync(NewKey(), Ct))!));

        // The refusal is learned once: a second take goes straight to the script.
        Assert.Equal("an-authorization", Encoding.UTF8.GetString((await store.TryTakeAsync(NewKey(), Ct))!));
        database.Verify(
            db => db.StringGetDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()),
            Times.Once);
    }

    /// <summary>
    /// A server too busy to serve one take is still a server that knows the command, so the next take
    /// must attempt it again rather than spend the process's life on the slower path.
    /// </summary>
    /// <remarks>
    /// The two cases are indistinguishable at the moment of the refusal, because the property naming the
    /// kind of error is published as experimental. What tells them apart is whether the script answered.
    /// </remarks>
    [Fact]
    public async Task TryTakeAsync_ARefusalTheScriptCannotAnswerEither_LeavesTheSingleCommandInUse()
    {
        var database = new Mock<IDatabase>();
        database
            .Setup(db => db.StringGetDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()))
            .ThrowsAsync(UnknownCommand());
        database
            .Setup(db => db.ScriptEvaluateAsync(
                It.IsAny<string>(),
                It.IsAny<RedisKey[]>(),
                It.IsAny<RedisValue[]>(),
                It.IsAny<CommandFlags>()))
            .ThrowsAsync(UnknownCommand());

        var connection = new Mock<IConnectionMultiplexer>();
        connection.Setup(c => c.GetDatabase(It.IsAny<int>(), It.IsAny<object>())).Returns(database.Object);

        var store = new RedisTakeOnceStore(connection.Object);

        await Assert.ThrowsAsync<RedisServerException>(() => store.TryTakeAsync(NewKey(), Ct));
        await Assert.ThrowsAsync<RedisServerException>(() => store.TryTakeAsync(NewKey(), Ct));

        database.Verify(
            db => db.StringGetDeleteAsync(It.IsAny<RedisKey>(), It.IsAny<CommandFlags>()),
            Times.Exactly(2));
    }
}
