// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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

    /// <summary>
    /// The receiver these streams belong to. One value throughout: what these tests exercise is the
    /// queue behind a stream, and the pair being the key has its own row rather than riding along
    /// silently in every other.
    /// </summary>
    private const string ReceiverId = "receiver-a";

    private static readonly RedisOutboxOptions Options = new();

    private RedisEventOutbox NewOutbox() => new(garnet.Connection, Options);

    /// <summary>
    /// The key the outbox stores under, spelled out here rather than taken from the implementation: a
    /// test composing the key by calling the code under test pins nothing, and this shape survives a
    /// rolling deploy where the two ends are two code versions.
    /// </summary>
    private static string StoredKeyOf(string streamId, string suffix, string receiverId = ReceiverId)
        => "Abblix.SharedSignals:RedisEventOutbox:"
           + $"{{{Uri.EscapeDataString(receiverId)}:{Uri.EscapeDataString(streamId)}}}:{suffix}";

    [Fact]
    public async Task Enqueue_KeepsOrder_AndPendingHonorsTheLimit()
    {
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-2", "b.b.b"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-3", "c.c.c"), TestContext.Current.CancellationToken);

        Assert.Equal(
            ["jti-1", "jti-2"],
            (await outbox.PendingAsync(ReceiverId, streamId, 2, TestContext.Current.CancellationToken))
            .Select(item => item.JwtId));
        Assert.Equal(3, (await outbox.PendingAsync(ReceiverId, streamId, null, TestContext.Current.CancellationToken)).Count);
        Assert.Empty(await outbox.PendingAsync(ReceiverId, streamId, 0, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Acknowledge_RemovesByName_AndClearDropsTheStream()
    {
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync(
            ReceiverId, streamId,
            new OutboxItem("jti-2", "b.b.b", IsStatusAnnouncement: true),
            TestContext.Current.CancellationToken);

        await outbox.AcknowledgeAsync(ReceiverId, streamId, ["jti-1"], TestContext.Current.CancellationToken);

        var remaining = Assert.Single(
            await outbox.PendingAsync(ReceiverId, streamId, null, TestContext.Current.CancellationToken));
        Assert.Equal("jti-2", remaining.JwtId);
        // The announcement flag is part of the item, and delivery filtering depends on it
        // surviving the round trip.
        Assert.True(remaining.IsStatusAnnouncement);

        await outbox.ClearAsync(ReceiverId, streamId, TestContext.Current.CancellationToken);
        Assert.Empty(await outbox.PendingAsync(ReceiverId, streamId, null, TestContext.Current.CancellationToken));
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
                ReceiverId, streamId, new OutboxItem(jwtId, compactToken), TestContext.Current.CancellationToken);

        async Task AcknowledgeAsync(RedisEventOutbox outbox, string ownPrefix)
            => await outbox.AcknowledgeAsync(
                ReceiverId, streamId,
                [.. Enumerable.Range(0, 50).Select(i => $"{ownPrefix}-{i}")],
                TestContext.Current.CancellationToken);

        await Task.WhenAll(
            Enumerable.Range(0, 50).Select(i => EnqueueAsync(first, $"a-{i}", "a.a.a"))
            .Concat(Enumerable.Range(0, 50).Select(i => EnqueueAsync(second, $"b-{i}", "b.b.b"))));

        var pending = await first.PendingAsync(ReceiverId, streamId, null, TestContext.Current.CancellationToken);
        Assert.Equal(100, pending.Count);
        Assert.Equal(100, pending.Select(item => item.JwtId).Distinct().Count());

        // Concurrent acknowledgements from both instances: each removes exactly its own half.
        await Task.WhenAll(AcknowledgeAsync(first, "a"), AcknowledgeAsync(second, "b"));

        Assert.Empty(await first.PendingAsync(ReceiverId, streamId, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AddSharedSignalsRedisOutbox_WinsOverTheRoleRegistration_AndWiresAWorkingOutbox()
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
        services.AddSharedSignalsRedisOutbox();

        var reversed = new ServiceCollection();
        reversed.AddSingleton<IConnectionMultiplexer>(garnet.Connection);
        reversed.AddSharedSignalsRedisOutbox();
        reversed.TryAddSingleton<IEventOutbox, NeverCalledOutbox>();
        await using (var reversedProvider = reversed.BuildServiceProvider())
        {
            Assert.IsType<RedisEventOutbox>(reversedProvider.GetRequiredService<IEventOutbox>());
        }

        await using var provider = services.BuildServiceProvider();
        var outbox = Assert.IsType<RedisEventOutbox>(provider.GetRequiredService<IEventOutbox>());

        var streamId = NewStreamId();
        await outbox.EnqueueAsync(
            ReceiverId, streamId, new OutboxItem("jti-di", "x.y.z"), TestContext.Current.CancellationToken);
        Assert.Equal(
            "jti-di",
            Assert.Single(await outbox.PendingAsync(ReceiverId, streamId, null, TestContext.Current.CancellationToken)).JwtId);
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
            StoredKeyOf(streamId, "queue"), "not a list");

        await Assert.ThrowsAsync<RedisServerException>(
            () => outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-1", "a.a.a"), ct));
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
        var itemsKey = StoredKeyOf(streamId, "items");

        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-1", "a.a.a"), ct);
        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-broken", "b.b.b"), ct);
        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-3", "c.c.c"), ct);
        await garnet.Connection.GetDatabase().HashSetAsync(itemsKey, "jti-broken", planted);

        var pending = await outbox.PendingAsync(ReceiverId, streamId, null, ct);
        Assert.Equal(["jti-1", "jti-3"], pending.Select(item => item.JwtId));

        // And it is gone rather than skipped forever: the next pass sees a queue of exactly the
        // healthy items, so the broken one costs no work and no space from here on.
        Assert.Equal(2, (await outbox.PendingAsync(ReceiverId, streamId, null, ct)).Count);
        Assert.Equal(
            2,
            await garnet.Connection.GetDatabase().ListLengthAsync(
                StoredKeyOf(streamId, "queue")));
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
        var queueKey = (RedisKey)StoredKeyOf(streamId, "queue");
        var itemsKey = (RedisKey)StoredKeyOf(streamId, "items");

        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-1", "a.a.a"), ct);

        var database = garnet.Connection.GetDatabase();
        Assert.NotNull(await database.KeyTimeToLiveAsync(queueKey));
        Assert.NotNull(await database.KeyTimeToLiveAsync(itemsKey));

        // Wind it down, then enqueue again: the expiry measures inactivity, so a stream still
        // receiving events must never reach it.
        await database.KeyExpireAsync(queueKey, TimeSpan.FromSeconds(5));
        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-2", "b.b.b"), ct);

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

        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("same", "first"), ct);
        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("same", "second"), ct);

        var item = Assert.Single(await outbox.PendingAsync(ReceiverId, streamId, null, ct));
        Assert.Equal("second", item.CompactToken);

        // One acknowledgement is enough, because there is one listing.
        await outbox.AcknowledgeAsync(ReceiverId, streamId, ["same"], ct);
        Assert.Empty(await outbox.PendingAsync(ReceiverId, streamId, null, ct));
    }

    /// <summary>
    /// A half with nothing in it is refused at every entry point, whichever half it is.
    /// </summary>
    /// <remarks>
    /// Ordinary argument checking rather than a guard with a consequence: an identifier with nothing in
    /// it is not an identifier. Said plainly because the first version of this row claimed an empty half
    /// would let a second pair address the same queue, which the escaping already makes impossible - and
    /// a guard defended by a false reason is a guard somebody deletes.
    /// </remarks>
    [Theory]
    [InlineData("", "s-1")]
    [InlineData("receiver-a", "")]
    public async Task AnEmptyHalfOfTheKey_IsRefused(string receiverId, string streamId)
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();

        await Assert.ThrowsAsync<ArgumentException>(
            () => outbox.EnqueueAsync(receiverId, streamId, new OutboxItem("jti-1", "a.a.a"), ct));
        await Assert.ThrowsAsync<ArgumentException>(() => outbox.PendingAsync(receiverId, streamId, null, ct));
        await Assert.ThrowsAsync<ArgumentException>(
            () => outbox.AcknowledgeAsync(receiverId, streamId, ["jti-1"], ct));
        await Assert.ThrowsAsync<ArgumentException>(() => outbox.ClearAsync(receiverId, streamId, ct));
    }

    /// <summary>
    /// An identifier carrying a brace is served, and the keys the outbox actually wrote still share one
    /// cluster hash tag.
    /// </summary>
    /// <remarks>
    /// It used to be refused, because a raw <c>}</c> ended the tag early or emptied it, and a stream whose
    /// two keys hash to different slots fails every multi-key call under Cluster. Escaping each half closed
    /// that by construction, so the refusal went with the condition it watched. Only <c>}</c> does
    /// anything at all, and only on the RECEIVER does it empty the tag rather than merely cut it - which
    /// is why the rows below carry the other positions as their own controls. Dropping the escaping from
    /// the receiver half kills exactly the rows whose closing brace LEADS the receiver: everything else
    /// survives, including a closing brace that does not lead - it cuts the tag short without emptying
    /// it, and both keys are cut identically, so they stay together.
    /// <para>
    /// The keys are READ BACK FROM THE SERVER rather than composed here, and that is the whole row. A first
    /// version of it built the expected key with the test's own escaping helper and compared that against
    /// itself: dropping the escaping from the outbox killed nothing at all, because both sides moved
    /// together. Every other row in this file plants at a composed key and so does notice, but only for an
    /// identifier that escaping CHANGES - and the receiver and the GUID stream ids escape to themselves.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("}", false)]
    [InlineData("}leading", false)]
    [InlineData("nested{}braces", false)]
    [InlineData("}", true)]
    [InlineData("}leading", true)]
    [InlineData("{leading", true)]
    [InlineData("nested{}braces", true)]
    public async Task AnIdentifierCarryingABrace_IsServedAndKeepsOneHashTag(string prefix, bool onTheReceiver)
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();

        // The GUID half is what finds the written keys again without assuming how the brace was spelled.
        var marker = NewStreamId();
        var streamId = onTheReceiver ? marker : prefix + marker;
        var receiverId = onTheReceiver ? prefix + ReceiverId : ReceiverId;

        await outbox.EnqueueAsync(receiverId, streamId, new OutboxItem("jti-1", "a.a.a"), ct);

        Assert.Equal("jti-1", Assert.Single(await outbox.PendingAsync(receiverId, streamId, null, ct)).JwtId);

        var written = garnet.Connection.GetServer(garnet.Connection.GetEndPoints()[0])
            .Keys(pattern: $"Abblix.SharedSignals:RedisEventOutbox:*{marker}*")
            .Select(key => (string)key!)
            .ToArray();

        Assert.Equal(2, written.Length);
        Assert.Equal(TagOf(written[0]), TagOf(written[1]));

        // Non-emptiness is the assertion that matters: an empty tag does not apply, and Redis then
        // hashes the whole key, which puts these two on different slots because they differ by suffix.
        Assert.NotEmpty(TagOf(written[0]));
        Assert.DoesNotContain('}', TagOf(written[0]));
    }

    /// <summary>
    /// Two pairs whose halves join to the same text keep separate queues.
    /// </summary>
    /// <remarks>
    /// This is what the escaping buys, and nothing else in this file measures it: without it the key of
    /// receiver "a:b" stream "c" is the key of receiver "a" stream "b:c", which is the defect this
    /// branch fixed arriving a second time through the key that fixed it. The other rows cannot see it
    /// because a receiver named <c>receiver-a</c> and a GUID stream escape to themselves.
    /// </remarks>
    [Fact]
    public async Task TwoPairsThatJoinAlike_DoNotShareAQueue()
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();
        var marker = NewStreamId();

        await outbox.EnqueueAsync($"{marker}a:b", "c", new OutboxItem("for-the-first", "a.a.a"), ct);
        await outbox.EnqueueAsync($"{marker}a", "b:c", new OutboxItem("for-the-second", "b.b.b"), ct);

        Assert.Equal(
            "for-the-first",
            Assert.Single(await outbox.PendingAsync($"{marker}a:b", "c", null, ct)).JwtId);
        Assert.Equal(
            "for-the-second",
            Assert.Single(await outbox.PendingAsync($"{marker}a", "b:c", null, ct)).JwtId);
    }

    /// <summary>
    /// Two receivers that named their streams alike do not share a queue.
    /// </summary>
    /// <remarks>
    /// The defect was in the KEY, and each implementation composes its own, so the shared store test
    /// cannot speak for this one. What makes it sharp here is the acknowledgement: sharing a queue does
    /// not merely mix events, it lets either receiver acknowledge the other's and never see them again.
    /// </remarks>
    [Fact]
    public async Task TwoReceiversSharingAStreamName_DoNotShareAQueue()
    {
        var ct = TestContext.Current.CancellationToken;
        var outbox = NewOutbox();
        var streamId = NewStreamId();

        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("for-a", "a.a.a"), ct);
        await outbox.EnqueueAsync("receiver-b", streamId, new OutboxItem("for-b", "b.b.b"), ct);

        await outbox.AcknowledgeAsync(ReceiverId, streamId, ["for-a"], ct);

        Assert.Empty(await outbox.PendingAsync(ReceiverId, streamId, null, ct));
        Assert.Equal("for-b", Assert.Single(await outbox.PendingAsync("receiver-b", streamId, null, ct)).JwtId);
    }

    /// <summary>The text Redis hashes a key by: what stands between the first brace and the next.</summary>
    private static string TagOf(string key)
        => key[(key.IndexOf('{') + 1)..key.IndexOf('}')];

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

        await outbox.EnqueueAsync(ReceiverId, streamId, new OutboxItem("jti-1", "a.a.a", true), ct);

        var raw = (await garnet.Connection.GetDatabase().HashGetAsync(
            StoredKeyOf(streamId, "items"), "jti-1")).ToString();

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
            string receiverId,
            string streamId,
            OutboxItem item,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task<IReadOnlyList<OutboxItem>> PendingAsync(
            string receiverId,
            string streamId,
            int? maxCount = null,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task AcknowledgeAsync(
            string receiverId,
            string streamId,
            IReadOnlyCollection<string> jwtIds,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public Task ClearAsync(
            string receiverId,
            string streamId,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
