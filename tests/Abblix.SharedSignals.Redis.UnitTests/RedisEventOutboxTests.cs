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

using Abblix.SharedSignals.Redis;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
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

    [Fact]
    public async Task Enqueue_KeepsOrder_AndPendingHonorsTheLimit()
    {
        var outbox = new RedisEventOutbox(garnet.Connection);
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
        var outbox = new RedisEventOutbox(garnet.Connection);
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
        // The hole this package closes: two outbox instances - two transmitter replicas - hammer
        // one stream concurrently, and every mutation must survive. A whole-queue-as-one-value
        // implementation loses writes here by last-write-wins; server-side appends cannot.
        var first = new RedisEventOutbox(garnet.Connection);
        var second = new RedisEventOutbox(garnet.Connection);
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
        // The explicit host choice must win in ANY order relative to the role registration -
        // that is why the extension uses Replace rather than TryAdd - and the registration must
        // construct a working instance, which only the container itself can prove.
        var services = new ServiceCollection();
        services.AddSingleton<IConnectionMultiplexer>(garnet.Connection);
        services.AddSingleton<IEventOutbox, NeverCalledOutbox>();
        services.AddSsfRedisOutbox();

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
