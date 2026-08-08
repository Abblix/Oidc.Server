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

using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Abblix.SharedSignals.Redis.UnitTests;

/// <summary>
/// The Redis stream store against a live wire-compatible server: registrations survive whole,
/// ownership rides in the key, and the conditioned update refuses what nobody created.
/// </summary>
public sealed class RedisStreamStoreTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private RedisStreamStore NewStore() => new(garnet.Connection);

    /// <summary>A receiver unique per test, so the shared hash never couples test runs.</summary>
    private readonly string _receiver = $"receiver-{Guid.NewGuid():N}";

    private StreamState NewState(string streamId, string status = StreamStatuses.Enabled) => new()
    {
        ReceiverId = _receiver,
        Status = status,
        SubjectsMode = StreamSubjectsMode.All,
        Configuration = new StreamConfiguration
        {
            StreamId = streamId,
            Issuer = "https://transmitter.example.com",
            Audiences = ["https://receiver.example.com/events"],
            EventsDelivered = ["https://transmitter.example.com/events/example"],
            Delivery = new PushDeliveryMethod(new Uri("https://receiver.example.com/events")),
        },
    };

    /// <summary>
    /// A registration survives the round-trip whole - the polymorphic delivery method included, which
    /// is the member a careless serialization flattens into an empty object without an error.
    /// </summary>
    [Fact]
    public async Task ACreatedStream_IsFoundWhole_AndASecondCreateIsRefused()
    {
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");

        Assert.True(await store.TryCreateAsync(NewState(streamId), TestContext.Current.CancellationToken));
        Assert.False(await store.TryCreateAsync(NewState(streamId), TestContext.Current.CancellationToken));

        var found = await store.FindAsync(_receiver, streamId, TestContext.Current.CancellationToken);
        Assert.NotNull(found);
        Assert.Equal(_receiver, found.ReceiverId);
        Assert.Equal(StreamSubjectsMode.All, found.SubjectsMode);
        var delivery = Assert.IsType<PushDeliveryMethod>(found.Configuration.Delivery);
        Assert.Equal(new Uri("https://receiver.example.com/events"), delivery.EndpointUrl);
    }

    /// <summary>
    /// Update replaces what exists and refuses what does not, atomically: an exists-then-set pair
    /// would let a concurrent delete be silently undone by the set that lost the race.
    /// </summary>
    [Fact]
    public async Task Update_ReplacesTheExisting_AndRefusesTheAbsent()
    {
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");

        Assert.False(await store.UpdateAsync(NewState(streamId), TestContext.Current.CancellationToken));

        Assert.True(await store.TryCreateAsync(NewState(streamId), TestContext.Current.CancellationToken));
        Assert.True(await store.UpdateAsync(NewState(streamId, StreamStatuses.Paused), TestContext.Current.CancellationToken));

        var found = await store.FindAsync(_receiver, streamId, TestContext.Current.CancellationToken);
        Assert.Equal(StreamStatuses.Paused, found!.Status);
    }

    /// <summary>
    /// Ownership rides in the key: the wrong receiver finds nothing and lists nothing, while the
    /// dispatcher's all-streams view still sees the registration.
    /// </summary>
    [Fact]
    public async Task AStream_IsInvisible_UnderAnotherReceiver()
    {
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");
        await store.TryCreateAsync(NewState(streamId), TestContext.Current.CancellationToken);

        Assert.Null(await store.FindAsync($"{_receiver}-other", streamId, TestContext.Current.CancellationToken));
        Assert.Empty(await store.ListAsync($"{_receiver}-other", TestContext.Current.CancellationToken));
        Assert.Contains(
            await store.ListAllAsync(TestContext.Current.CancellationToken),
            stream => stream.ReceiverId == _receiver && stream.StreamId == streamId);
    }

    /// <summary>
    /// The composite field escapes its parts, so a receiver id containing the separator cannot
    /// address - or shadow - another receiver's stream. The receiver id is whatever the host's
    /// authentication produced; the store must not trust its alphabet.
    /// </summary>
    [Fact]
    public async Task AReceiverIdCarryingTheSeparator_CannotReachAForeignStream()
    {
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");
        await store.TryCreateAsync(NewState(streamId), TestContext.Current.CancellationToken);

        // Wears the composite of receiver and stream as its RECEIVER id, with an empty stream id -
        // unescaped joining would produce the very same field.
        Assert.Null(await store.FindAsync($"{_receiver}|{streamId}", string.Empty, TestContext.Current.CancellationToken));
        Assert.Empty(await store.ListAsync($"{_receiver}|{streamId}", TestContext.Current.CancellationToken));
    }

    /// <summary>Deletion answers what it did, once.</summary>
    [Fact]
    public async Task Delete_AnswersTrueOnce()
    {
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");
        await store.TryCreateAsync(NewState(streamId), TestContext.Current.CancellationToken);

        Assert.True(await store.DeleteAsync(_receiver, streamId, TestContext.Current.CancellationToken));
        Assert.False(await store.DeleteAsync(_receiver, streamId, TestContext.Current.CancellationToken));
        Assert.Null(await store.FindAsync(_receiver, streamId, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The registration replaces the in-memory default whichever side registers first - the same
    /// order-independence contract the outbox registration carries.
    /// </summary>
    [Fact]
    public void TheRegistration_WinsOverTheDefault_InAnyOrder()
    {
        var before = new ServiceCollection();
        before.AddSingleton<StackExchange.Redis.IConnectionMultiplexer>(garnet.Connection);
        before.AddSsfRedisStreamStore();
        before.TryAddSingleton<IStreamStore, InMemoryStreamStore>();
        Assert.IsType<RedisStreamStore>(
            before.BuildServiceProvider().GetRequiredService<IStreamStore>());

        var after = new ServiceCollection();
        after.AddSingleton<StackExchange.Redis.IConnectionMultiplexer>(garnet.Connection);
        after.TryAddSingleton<IStreamStore, InMemoryStreamStore>();
        after.AddSsfRedisStreamStore();
        Assert.IsType<RedisStreamStore>(
            after.BuildServiceProvider().GetRequiredService<IStreamStore>());
    }
}
