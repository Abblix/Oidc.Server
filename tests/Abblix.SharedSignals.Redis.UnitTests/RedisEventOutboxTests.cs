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

using Abblix.SharedSignals.Transmitter;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;
using Xunit;

namespace Abblix.SharedSignals.Redis.UnitTests;

/// <summary>
/// Pins the Redis-native outbox against a REAL Redis-protocol server - the embedded Garnet the
/// fixture starts - because the whole point of this implementation is server-side atomicity,
/// which a mock of the client API cannot witness. The concurrency test is the reason the
/// package exists: mutations from independent instances must compose, where the
/// one-value-per-queue design loses them.
/// </summary>
public sealed class RedisEventOutboxTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    /// <summary>
    /// Streams are namespaced per test: the class fixture is one shared server, and a
    /// collision between tests would be a test defect wearing a product one's clothes.
    /// </summary>
    private static string NewStreamId() => $"s-{Guid.NewGuid():N}";

    private static readonly RedisOutboxOptions Options = new();

    private RedisEventOutbox NewOutbox() => new(garnet.Connection, Options);

    [Fact]
    public async Task Enqueue_KeepsOrder_AndPendingHonorsTheLimit()
    {
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-2", "b.b.b"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-3", "c.c.c"), TestContext.Current.CancellationToken);

        Assert.Equal(
            ["jti-1", "jti-2"],
            (await outbox.PendingAsync(streamId, 2, TestContext.Current.CancellationToken))
            .Select(item => item.JwtId));
        Assert.Equal(3, (await outbox.PendingAsync(streamId, null, TestContext.Current.CancellationToken)).Count);
        Assert.Empty(await outbox.PendingAsync(streamId, 0, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Acknowledge_RemovesByName_AndClearDropsTheStream()
    {
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync(
            streamId,
            new OutboxItem("jti-2", "b.b.b", IsStatusAnnouncement: true),
            TestContext.Current.CancellationToken);

        await outbox.AcknowledgeAsync(streamId, ["jti-1"], TestContext.Current.CancellationToken);

        var remaining = Assert.Single(
            await outbox.PendingAsync(streamId, null, TestContext.Current.CancellationToken));
        Assert.Equal("jti-2", remaining.JwtId);
        // The announcement flag is part of the item, and delivery filtering depends on it
        // surviving the round trip.
        Assert.True(remaining.IsStatusAnnouncement);

        await outbox.ClearAsync(streamId, TestContext.Current.CancellationToken);
        Assert.Empty(await outbox.PendingAsync(streamId, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ConcurrentInstances_ComposeInsteadOfOverwriting()
    {
        // The hole this package closes: two transmitter replicas hammer one stream concurrently, and
        // every mutation must survive. A whole-queue-as-one-value implementation loses writes here by
        // last-write-wins; server-side appends cannot.
        //
        // TWO CONNECTIONS, not two objects over one. The class holds no state but its database handle,
        // so two instances over one multiplexer are one instance - and the client keeps the physical
        // connection for a whole transaction, so their commands never interleave at the server. Built
        // that way this test would exclude the very concurrency it claims to measure.
        await using var secondConnection = garnet.CreateConnection();
        var first = NewOutbox();
        var second = new RedisEventOutbox(secondConnection, Options);
        var streamId = NewStreamId();

        async Task EnqueueAsync(RedisEventOutbox outbox, string jwtId, string compactToken)
            => await outbox.EnqueueAsync(
                streamId, new OutboxItem(jwtId, compactToken), TestContext.Current.CancellationToken);

        async Task AcknowledgeAsync(RedisEventOutbox outbox, string ownPrefix)
            => await outbox.AcknowledgeAsync(
                streamId,
                [.. Enumerable.Range(0, 50).Select(i => $"{ownPrefix}-{i}")],
                TestContext.Current.CancellationToken);

        await Task.WhenAll(
            Enumerable.Range(0, 50).Select(i => EnqueueAsync(first, $"a-{i}", "a.a.a"))
            .Concat(Enumerable.Range(0, 50).Select(i => EnqueueAsync(second, $"b-{i}", "b.b.b"))));

        var pending = await first.PendingAsync(streamId, null, TestContext.Current.CancellationToken);
        Assert.Equal(100, pending.Count);
        Assert.Equal(100, pending.Select(item => item.JwtId).Distinct().Count());

        // Concurrent acknowledgements from both instances: each removes exactly its own half.
        await Task.WhenAll(AcknowledgeAsync(first, "a"), AcknowledgeAsync(second, "b"));

        Assert.Empty(await first.PendingAsync(streamId, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AddSsfRedisOutbox_WinsOverTheRoleRegistration_AndWiresAWorkingOutbox()
    {
        // The explicit host choice must win in ANY order relative to the role registration - that is
        // why the extension uses Replace rather than TryAdd - and the registration must construct a
        // working instance, which only the container itself can prove.
        //
        // The stand-in mirrors how the ROLE registers the default (TryAdd), not how a host would
        // register an override: with AddSingleton the later call simply wins, so the test would pass
        // in the order it exercises and fail in the other, while claiming both.
        var services = new ServiceCollection();
        services.AddSingleton<IConnectionMultiplexer>(garnet.Connection);
        services.TryAddSingleton<IEventOutbox, NeverCalledOutbox>();
        services.AddSsfRedisOutbox();

        var reversed = new ServiceCollection();
        reversed.AddSingleton<IConnectionMultiplexer>(garnet.Connection);
        reversed.AddSsfRedisOutbox();
        reversed.TryAddSingleton<IEventOutbox, NeverCalledOutbox>();
        await using (var reversedProvider = reversed.BuildServiceProvider())
        {
            Assert.IsType<RedisEventOutbox>(reversedProvider.GetRequiredService<IEventOutbox>());
        }

        await using var provider = services.BuildServiceProvider();
        var outbox = Assert.IsType<RedisEventOutbox>(provider.GetRequiredService<IEventOutbox>());

        var streamId = NewStreamId();
        await outbox.EnqueueAsync(
            streamId, new OutboxItem("jti-di", "x.y.z"), TestContext.Current.CancellationToken);
        Assert.Equal(
            "jti-di",
            Assert.Single(await outbox.PendingAsync(streamId, null, TestContext.Current.CancellationToken)).JwtId);
    }

    /// <summary>
    /// A command failing inside the mutation reaches the caller instead of being reported as success.
    /// </summary>
    /// <remarks>
    /// Redis has no rollback: a command that fails at execution time does not undo its predecessors,
    /// in a transaction or in a script. The difference is who learns about it. MULTI/EXEC reports the
    /// failure only inside the EXEC reply, so a caller that discards the per-command tasks is told
    /// "true" - and a signed event ends up in the hash with no listing, unreachable forever, while the
    /// dispatcher counts the stream as reached. The wrong-type key is the cheapest way to make one
    /// command fail on a real server.
    /// </remarks>
    [Fact]
    public async Task AFailedCommand_ReachesTheCaller()
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        // The queue key holds a string, so the append against it cannot succeed.
        await garnet.Connection.GetDatabase().StringSetAsync(
            $"Abblix.SharedSignals:RedisEventOutbox:{{{streamId}}}:queue", "not a list");

        await Assert.ThrowsAsync<RedisServerException>(
            () => outbox.EnqueueAsync(streamId, new OutboxItem("jti-1", "a.a.a"), ct));
    }

    /// <summary>
    /// One unreadable item costs itself and nothing else: the pass returns the healthy items around
    /// it and drops its listing, so the stream keeps draining.
    /// </summary>
    /// <remarks>
    /// Throwing instead would wedge the stream permanently - this read IS the delivery pass, nothing
    /// else removes an item, and acknowledgement only ever names an identifier a consumer read back.
    /// The half-shaped payload is the worse half of the pair: it parses, so a guard against null would
    /// pass it through, and an item with no identifier can be served and never acknowledged.
    /// </remarks>
    [Theory]
    [InlineData("this is not json")]
    [InlineData("""{"token":"a.a.a"}""")]
    public async Task AnUnreadableItem_DoesNotWedgeTheStream(string planted)
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();
        var streamId = NewStreamId();
        var itemsKey = $"Abblix.SharedSignals:RedisEventOutbox:{{{streamId}}}:items";

        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-1", "a.a.a"), ct);
        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-broken", "b.b.b"), ct);
        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-3", "c.c.c"), ct);
        await garnet.Connection.GetDatabase().HashSetAsync(itemsKey, "jti-broken", planted);

        var pending = await outbox.PendingAsync(streamId, null, ct);
        Assert.Equal(["jti-1", "jti-3"], pending.Select(item => item.JwtId));

        // And it is gone rather than skipped forever: the next pass sees a queue of exactly the
        // healthy items, so the broken one costs no work and no space from here on.
        Assert.Equal(2, (await outbox.PendingAsync(streamId, null, ct)).Count);
        Assert.Equal(
            2,
            await garnet.Connection.GetDatabase().ListLengthAsync(
                $"Abblix.SharedSignals:RedisEventOutbox:{{{streamId}}}:queue"));
    }

    /// <summary>
    /// A queue nobody adds to expires. Without a bound the queues of departed receivers accumulate
    /// forever, which is not the cache tier this store was chosen for.
    /// </summary>
    [Fact]
    public async Task AQueue_ExpiresWithoutNewEvents_AndTheClockRestarts()
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = new RedisEventOutbox(
            garnet.Connection, new RedisOutboxOptions { Retention = TimeSpan.FromHours(1) });
        var streamId = NewStreamId();
        var queueKey = (RedisKey)$"Abblix.SharedSignals:RedisEventOutbox:{{{streamId}}}:queue";
        var itemsKey = (RedisKey)$"Abblix.SharedSignals:RedisEventOutbox:{{{streamId}}}:items";

        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-1", "a.a.a"), ct);

        var database = garnet.Connection.GetDatabase();
        Assert.NotNull(await database.KeyTimeToLiveAsync(queueKey));
        Assert.NotNull(await database.KeyTimeToLiveAsync(itemsKey));

        // Wind it down, then enqueue again: the expiry measures inactivity, so a stream still
        // receiving events must never reach it.
        await database.KeyExpireAsync(queueKey, TimeSpan.FromSeconds(5));
        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-2", "b.b.b"), ct);

        Assert.True(await database.KeyTimeToLiveAsync(queueKey) > TimeSpan.FromMinutes(30));
    }

    /// <summary>
    /// A repeated identifier updates one item instead of destroying one and duplicating another.
    /// </summary>
    /// <remarks>
    /// A plain append lists the identifier twice while the hash keeps a single payload, so the first
    /// event is destroyed and the second is delivered twice. The dispatcher mints a fresh identifier
    /// per stream per event, so this cannot arise in-repo - but the interface is public, and the
    /// destructive reading is the one a host would never expect.
    /// </remarks>
    [Fact]
    public async Task ARepeatedIdentifier_UpdatesRatherThanDuplicates()
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        await outbox.EnqueueAsync(streamId, new OutboxItem("same", "first"), ct);
        await outbox.EnqueueAsync(streamId, new OutboxItem("same", "second"), ct);

        var item = Assert.Single(await outbox.PendingAsync(streamId, null, ct));
        Assert.Equal("second", item.CompactToken);

        // One acknowledgement is enough, because there is one listing.
        await outbox.AcknowledgeAsync(streamId, ["same"], ct);
        Assert.Empty(await outbox.PendingAsync(streamId, null, ct));
    }

    /// <summary>
    /// A stream identifier that would empty the cluster hash tag is refused at every entry point.
    /// </summary>
    /// <remarks>
    /// Redis reads the tag between the first brace and the first closing one after it. When that text
    /// is empty the tag does not apply and the whole key is hashed, so a stream's two keys land on
    /// different slots and every multi-key call fails CROSSSLOT under Cluster. Nested braces are
    /// harmless and stay allowed. The built-in dispatcher mints GUIDs, but the store interface is
    /// public and a host's identifiers are its own.
    /// </remarks>
    [Theory]
    [InlineData("")]
    [InlineData("}")]
    [InlineData("}leading")]
    public async Task AStreamIdBreakingTheHashTag_IsRefused(string streamId)
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();

        await Assert.ThrowsAsync<ArgumentException>(
            () => outbox.EnqueueAsync(streamId, new OutboxItem("jti-1", "a.a.a"), ct));
        await Assert.ThrowsAsync<ArgumentException>(() => outbox.PendingAsync(streamId, null, ct));
        await Assert.ThrowsAsync<ArgumentException>(() => outbox.AcknowledgeAsync(streamId, ["jti-1"], ct));
        await Assert.ThrowsAsync<ArgumentException>(() => outbox.ClearAsync(streamId, ct));
    }

    /// <summary>
    /// The stored shape does not follow C# member names. Redis holds these items across a rolling
    /// deploy, so the two ends are two code versions: a rename would otherwise read every stored item
    /// back with null members rather than failing, and a null identifier is the one shape that can be
    /// served and never acknowledged.
    /// </summary>
    [Fact]
    public async Task TheStoredShape_IsPinned_NotDerivedFromCSharpNames()
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        await outbox.EnqueueAsync(streamId, new OutboxItem("jti-1", "a.a.a", true), ct);

        var raw = (await garnet.Connection.GetDatabase().HashGetAsync(
            $"Abblix.SharedSignals:RedisEventOutbox:{{{streamId}}}:items", "jti-1")).ToString();

        Assert.Contains("\"jti\":\"jti-1\"", raw, StringComparison.Ordinal);
        Assert.Contains("\"token\":\"a.a.a\"", raw, StringComparison.Ordinal);
        Assert.Contains("\"is_status_announcement\":true", raw, StringComparison.Ordinal);
    }

    /// <summary>
    /// The role registration the explicit choice must displace; reaching it would mean the
    /// Replace semantics broke, so every member says so instead of answering.
    /// </summary>
    private sealed class NeverCalledOutbox : IEventOutbox
    {
        public Task EnqueueAsync(
            string streamId, OutboxItem item, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<OutboxItem>> PendingAsync(
            string streamId, int? maxCount = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task AcknowledgeAsync(
            string streamId,
            IReadOnlyCollection<string> jwtIds,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task ClearAsync(string streamId, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
