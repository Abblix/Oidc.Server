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

        var found = await store.FindAsync("receiver-a", "s-1", TestContext.Current.CancellationToken);
        Assert.Same(stream, found);
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
    public async Task Update_ReplacesTheSnapshot_AndRefusesTheAbsent()
    {
        var store = new InMemoryStreamStore();
        var stream = CreateStream("receiver-a", "s-1");
        await store.TryCreateAsync(stream, TestContext.Current.CancellationToken);

        var paused = stream with { Status = StreamStatuses.Paused };
        Assert.True(await store.UpdateAsync(paused, TestContext.Current.CancellationToken));
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
