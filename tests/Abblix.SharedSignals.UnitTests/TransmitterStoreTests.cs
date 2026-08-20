// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the in-memory stream store's contract: creation refuses a duplicate, reads are scoped
/// by receiver, an update replaces only what exists, and a delete answers whether anything was
/// there.
/// </summary>
public class TransmitterStoreTests
{
    private static StreamState CreateStream(string receiverId, string streamId) => new()
    {
        ReceiverId = receiverId,
        SubjectsMode = StreamSubjectsMode.None,
        Configuration = new StreamConfiguration
        {
            StreamId = streamId,
            Issuer = "https://tr.example.com",
            Audiences = ["https://receiver.example.com"],
            EventsDelivered = [],
            Delivery = new PollDeliveryMethod(new Uri($"https://tr.example.com/poll/{streamId}")),
        },
    };

    [Fact]
    public async Task Create_RefusesADuplicate_AndFindReadsItBack()
    {
        var store = new InMemoryStreamStore();
        var stream = CreateStream("receiver-a", "s-1");

        Assert.True(await store.TryCreateAsync(stream, TestContext.Current.CancellationToken));
        Assert.False(await store.TryCreateAsync(stream, TestContext.Current.CancellationToken));

        // Read back by value, not by reference: the store stamps a version on what it keeps, so
        // the copy on record is a new instance and the version is the store's to mint.
        var found = await store.FindAsync("receiver-a", "s-1", TestContext.Current.CancellationToken);
        Assert.Equal(stream.StreamId, found!.StreamId);
        Assert.NotNull(found.Version);
        Assert.Null(await store.FindAsync("receiver-b", "s-1", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task List_IsScopedByReceiver_AndListAllSeesEverything()
    {
        var store = new InMemoryStreamStore();
        await store.TryCreateAsync(CreateStream("receiver-a", "s-1"), TestContext.Current.CancellationToken);
        await store.TryCreateAsync(CreateStream("receiver-a", "s-2"), TestContext.Current.CancellationToken);
        await store.TryCreateAsync(CreateStream("receiver-b", "s-3"), TestContext.Current.CancellationToken);

        Assert.Equal(2, (await store.ListAsync("receiver-a", TestContext.Current.CancellationToken)).Count);
        Assert.Empty(await store.ListAsync("receiver-c", TestContext.Current.CancellationToken));
        Assert.Equal(3, (await store.ListAllAsync(TestContext.Current.CancellationToken)).Count);
    }

    [Fact]
    public async Task Update_ReplacesTheSnapshotItWasReadFrom_AndRefusesEveryOther()
    {
        var store = new InMemoryStreamStore();
        await store.TryCreateAsync(CreateStream("receiver-a", "s-1"), TestContext.Current.CancellationToken);

        var read = await store.FindAsync("receiver-a", "s-1", TestContext.Current.CancellationToken);
        var paused = read! with { Status = StreamStatuses.Paused };
        Assert.True(await store.UpdateAsync(paused, TestContext.Current.CancellationToken));

        var afterwards = await store.FindAsync("receiver-a", "s-1", TestContext.Current.CancellationToken);
        Assert.Equal(StreamStatuses.Paused, afterwards!.Status);

        // The write that made the change is now stale, and a second one built from it is refused
        // rather than silently overwriting what landed in between. This is the whole point: two
        // callers reading the same stream and both writing used to end with one change lost, both
        // answered success.
        Assert.False(await store.UpdateAsync(
            read with { Status = StreamStatuses.Disabled }, TestContext.Current.CancellationToken));
        Assert.Equal(
            StreamStatuses.Paused,
            (await store.FindAsync("receiver-a", "s-1", TestContext.Current.CancellationToken))!.Status);

        Assert.False(await store.UpdateAsync(
            CreateStream("receiver-a", "missing"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Delete_AnswersWhetherAnythingWasThere()
    {
        var store = new InMemoryStreamStore();
        await store.TryCreateAsync(CreateStream("receiver-a", "s-1"), TestContext.Current.CancellationToken);

        Assert.True(await store.DeleteAsync("receiver-a", "s-1", TestContext.Current.CancellationToken));
        Assert.False(await store.DeleteAsync("receiver-a", "s-1", TestContext.Current.CancellationToken));
        Assert.Null(await store.FindAsync("receiver-a", "s-1", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Outbox_KeepsEnqueueOrder_AcknowledgesByName_AndClearsWhole()
    {
        var outbox = new InMemoryEventOutbox();
        await outbox.EnqueueAsync("s-1", new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync("s-1", new OutboxItem("jti-2", "b.b.b"), TestContext.Current.CancellationToken);
        await outbox.EnqueueAsync("s-1", new OutboxItem("jti-3", "c.c.c"), TestContext.Current.CancellationToken);

        // Enqueue order is what keeps same-principal events in generation order across a pause
        // (SSF 1.0 Section 8.1.2.1); reading does not remove - redelivery is the protocols' own
        // semantics.
        var head = await outbox.PendingAsync("s-1", 2, TestContext.Current.CancellationToken);
        Assert.Equal(["jti-1", "jti-2"], head.Select(item => item.JwtId));
        Assert.Equal(3, (await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken)).Count);

        await outbox.AcknowledgeAsync("s-1", ["jti-1", "jti-3"], TestContext.Current.CancellationToken);
        var remaining = Assert.Single(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.Equal("jti-2", remaining.JwtId);

        await outbox.ClearAsync("s-1", TestContext.Current.CancellationToken);
        Assert.Empty(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.Empty(await outbox.PendingAsync("never-seen", null, TestContext.Current.CancellationToken));
    }
}
