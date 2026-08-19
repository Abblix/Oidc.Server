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

using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;
using Xunit;
using StreamConfiguration = Abblix.SharedSignals.Model.StreamConfiguration;

namespace Abblix.SharedSignals.Redis.UnitTests;

/// <summary>
/// The Redis stream store against a live wire-compatible server: registrations survive whole,
/// ownership rides in the key, and the conditioned update refuses what nobody created.
/// </summary>
public sealed class RedisStreamStoreTests(GarnetFixture garnet) : IClassFixture<GarnetFixture>
{
    private static readonly SharedSignalsTransmitterOptions Options = new() { Issuer = "https://transmitter.example.com" };

    /// <summary>
    /// The key the store writes under, spelled out here rather than asked of the store: the tests that
    /// plant a broken entry or read the raw bytes have to address the same place the store does, and a
    /// helper on the store would let both sides move together and prove nothing.
    /// </summary>
    private static readonly RedisKey HashKey =
        $"Abblix.SharedSignals:RedisStreamStore:{Uri.EscapeDataString(Options.Issuer)}";

    private RedisStreamStore NewStore() => new(garnet.Connection, Options);

    /// <summary>A receiver unique per test, so the shared hash never couples test runs.</summary>
    private readonly string _receiver = $"receiver-{Guid.NewGuid():N}";

    private StreamState NewState(string streamId, string status = StreamStatuses.Enabled)
        => NewState(_receiver, streamId, status);

    private static StreamState NewState(string receiverId, string streamId, string status = StreamStatuses.Enabled) => new()
    {
        ReceiverId = receiverId,
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

        var ct = TestContext.Current.CancellationToken;

        Assert.False(await store.UpdateAsync(NewState(streamId), ct));

        Assert.True(await store.TryCreateAsync(NewState(streamId), ct));

        // The write carries the version it was read with, which is what the script compares.
        var read = await store.FindAsync(_receiver, streamId, ct);
        Assert.True(await store.UpdateAsync(read! with { Status = StreamStatuses.Paused }, ct));
        Assert.Equal(StreamStatuses.Paused, (await store.FindAsync(_receiver, streamId, ct))!.Status);

        // And the same write a second time is refused: it is now built from a stale copy, which is
        // exactly the shape that used to overwrite whatever landed in between.
        Assert.False(await store.UpdateAsync(read with { Status = StreamStatuses.Disabled }, ct));
        Assert.Equal(StreamStatuses.Paused, (await store.FindAsync(_receiver, streamId, ct))!.Status);
    }

    /// <summary>
    /// A registration written before versions existed can still be changed, once, after which it
    /// carries a version like any other.
    /// </summary>
    /// <remarks>
    /// The version arrived after this store had been shipping, so registrations the earlier build
    /// wrote carry no version member at all. A caller reads one, is handed a null version, and its
    /// write is then judged against a marker the stored document cannot contain - so every change to
    /// that stream is refused for as long as the stream exists, and the refusal reaches the receiver
    /// as a lost race that never happened. Nothing about it improves with the retry that refusal
    /// advises.
    /// </remarks>
    [Fact]
    public async Task AStreamStoredBeforeVersionsExisted_CanStillBeUpdated()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");

        await garnet.Connection.GetDatabase().HashSetAsync(
            HashKey,
            $"{Uri.EscapeDataString(_receiver)}|{Uri.EscapeDataString(streamId)}",
            WithoutVersion(NewState(streamId)));

        try
        {
            var read = await store.FindAsync(_receiver, streamId, ct);
            Assert.NotNull(read);
            Assert.Null(read.Version);

            Assert.True(await store.UpdateAsync(read with { Status = StreamStatuses.Paused }, ct));

            var updated = await store.FindAsync(_receiver, streamId, ct);
            Assert.Equal(StreamStatuses.Paused, updated!.Status);
            Assert.NotNull(updated.Version);

            // Ordinary from here on: the versionless copy no longer replaces anything, or admitting
            // it would leave the stream permanently unguarded instead of migrating it once.
            Assert.False(await store.UpdateAsync(read with { Status = StreamStatuses.Disabled }, ct));
            Assert.Equal(
                StreamStatuses.Paused, (await store.FindAsync(_receiver, streamId, ct))!.Status);
        }
        finally
        {
            await store.DeleteAsync(_receiver, streamId, ct);
        }
    }

    /// <summary>
    /// The same state as the build before versions wrote it: the member absent, not present and
    /// empty. Only absence is what those registrations carry, and the two are different shapes to
    /// anything comparing text.
    /// </summary>
    private static string WithoutVersion(StreamState state)
    {
        var document = JsonSerializer.SerializeToNode(
                state,
                new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } })!
            .AsObject();

        document.Remove("version");
        return document.ToJsonString();
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
    /// address another receiver's stream. The receiver id is whatever the host's authentication
    /// produced; the store must not trust its alphabet.
    /// </summary>
    /// <remarks>
    /// The pair is chosen so that UNESCAPED joining collides and escaped joining does not - both
    /// ("a|b", "c") and ("a", "b|c") produce the field "a|b|c" raw. An earlier version of this test
    /// used a receiver carrying the whole composite and an empty stream id, which does not collide
    /// even raw (it grows a trailing separator): it passed with the escaping removed, and proved
    /// nothing about it.
    /// </remarks>
    [Fact]
    public async Task AReceiverIdCarryingTheSeparator_CannotReachAForeignStream()
    {
        var store = NewStore();

        var victim = await store.TryCreateAsync(
            NewState(receiverId: $"{_receiver}|left", streamId: "right"),
            TestContext.Current.CancellationToken);
        Assert.True(victim);

        // Same characters, split one position later. Unescaped these address one field.
        Assert.Null(await store.FindAsync(
            _receiver, $"left|right", TestContext.Current.CancellationToken));

        Assert.True(await store.TryCreateAsync(
            NewState(receiverId: _receiver, streamId: "left|right"),
            TestContext.Current.CancellationToken));

        Assert.Equal(
            "right",
            (await store.FindAsync($"{_receiver}|left", "right", TestContext.Current.CancellationToken))!
                .StreamId);
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
    /// An update keeps meaning "no such stream" while OTHER connections write to the same registry.
    /// </summary>
    /// <remarks>
    /// The defect this pins is invisible from one multiplexer. A transaction conditioned on the field
    /// watches the KEY, and every stream of every receiver lives under one key - so any concurrent
    /// write aborts the commit, and the abort is indistinguishable from a missing stream. The
    /// management service turns that into a 404 while the update is silently dropped, and it happens
    /// precisely in the deployment this package is for: a transmitter past one replica. The second
    /// connection is what makes the writes concurrent at the SERVER rather than serialized by the
    /// client, so this test is worthless without it.
    /// </remarks>
    [Fact]
    public async Task Update_KeepsItsMeaning_WhileAnotherConnectionWrites()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");
        Assert.True(await store.TryCreateAsync(NewState(streamId), ct));

        await using var noisy = await ConnectionMultiplexer.ConnectAsync(garnet.Connection.Configuration);
        var neighbour = new RedisStreamStore(noisy, Options);
        var neighbourReceiver = $"{_receiver}-neighbour";
        var neighbourStream = Guid.NewGuid().ToString("N");
        Assert.True(await neighbour.TryCreateAsync(
            NewState(neighbourReceiver, neighbourStream), ct));

        using var noise = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var writing = Task.Run(
            async () =>
            {
                while (!noise.IsCancellationRequested)
                    await neighbour.UpdateAsync(NewState(neighbourReceiver, neighbourStream), noise.Token);
            },
            noise.Token);

        try
        {
            // Each write reads first, so it carries the version it is replacing. The neighbour's
            // traffic must not make any of these fail: the point is that a write is judged against
            // ITS OWN stream, never against whatever else the connection is doing.
            var refusals = 0;
            for (var attempt = 0; attempt < 200; attempt++)
            {
                var current = await store.FindAsync(_receiver, streamId, ct);
                if (!await store.UpdateAsync(current! with { Status = StreamStatuses.Paused }, ct))
                    refusals++;
            }

            Assert.Equal(0, refusals);
        }
        finally
        {
            await noise.CancelAsync();
            try
            {
                await writing;
            }
            catch (OperationCanceledException)
            {
                // Cancellation is how the writer is stopped, not a failure of it.
            }

            await neighbour.DeleteAsync(neighbourReceiver, neighbourStream, ct);
        }
    }

    /// <summary>
    /// One unreadable entry costs its own registration and nothing else: the listings skip it, so the
    /// dispatcher keeps delivering to everybody healthy, while a lookup naming that very stream still
    /// fails loudly rather than reporting it absent.
    /// </summary>
    [Fact]
    public async Task AnUnreadableEntry_IsSkippedByListings_AndThrowsOnItsOwnLookup()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore();
        var healthy = Guid.NewGuid().ToString("N");
        Assert.True(await store.TryCreateAsync(NewState(healthy), ct));

        // Written straight into the hash, the way a version with another shape would have left it.
        var broken = Guid.NewGuid().ToString("N");
        await garnet.Connection.GetDatabase().HashSetAsync(
            HashKey,
            $"{Uri.EscapeDataString(_receiver)}|{Uri.EscapeDataString(broken)}",
            "{not json at all");

        try
        {
            Assert.Contains(await store.ListAllAsync(ct), stream => stream.StreamId == healthy);
            Assert.DoesNotContain(await store.ListAsync(_receiver, ct), stream => stream.StreamId == broken);

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => store.FindAsync(_receiver, broken, ct));
        }
        finally
        {
            await store.DeleteAsync(_receiver, broken, ct);
        }
    }

    /// <summary>
    /// Everything a registration carries survives the round trip - the subjects a receiver added and
    /// removed above all, because they are polymorphic and a test building a minimal state never
    /// touches them.
    /// </summary>
    [Fact]
    public async Task AFullyPopulatedRegistration_SurvivesWhole()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");

        var stored = NewState(streamId, StreamStatuses.Paused) with
        {
            StatusReason = "receiver asked",
            AddedSubjects =
                [new StreamSubject(new IssSubSubject("https://account.example.com", "sub-1"), true)],
            RemovedSubjects = [new OpaqueSubject("opaque-2")],
            LastVerificationRequestAt = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.FromHours(3)),
        };

        Assert.True(await store.TryCreateAsync(stored, ct));

        var read = await store.FindAsync(_receiver, streamId, ct);
        Assert.NotNull(read);
        Assert.Equal(StreamStatuses.Paused, read.Status);
        Assert.Equal("receiver asked", read.StatusReason);
        Assert.Equal(stored.LastVerificationRequestAt, read.LastVerificationRequestAt);

        var added = Assert.IsType<IssSubSubject>(Assert.Single(read.AddedSubjects).Subject);
        Assert.Equal("sub-1", added.Subject);
        Assert.IsType<OpaqueSubject>(Assert.Single(read.RemovedSubjects));
    }

    /// <summary>
    /// The stored shape does not follow C# names. Both halves matter and both fail silently: an enum
    /// written as its ordinal turns reordering a vocabulary into a reinterpretation of every stored
    /// registration - a stream covering everyone comes back covering nobody - and a member written
    /// under its property name turns a rename into a reset, so a stream a receiver had paused comes
    /// back enabled.
    /// </summary>
    [Fact]
    public async Task TheStoredShape_IsPinned_NotDerivedFromCSharpNames()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore();
        var streamId = Guid.NewGuid().ToString("N");
        Assert.True(await store.TryCreateAsync(NewState(streamId, StreamStatuses.Paused), ct));

        var raw = (await garnet.Connection.GetDatabase().HashGetAsync(
            HashKey,
            $"{Uri.EscapeDataString(_receiver)}|{Uri.EscapeDataString(streamId)}")).ToString();

        Assert.Contains($"\"subjects_mode\":\"{nameof(StreamSubjectsMode.All)}\"", raw, StringComparison.Ordinal);
        Assert.Contains("\"receiver_id\":", raw, StringComparison.Ordinal);
        Assert.Contains($"\"status\":\"{StreamStatuses.Paused}\"", raw, StringComparison.Ordinal);

        // The computed duplicate of the configuration's own member is not written at all.
        Assert.DoesNotContain("\"StreamId\":", raw, StringComparison.Ordinal);
    }

    /// <summary>
    /// Two transmitters sharing one Redis keep separate registries. Without the issuer in the key they
    /// would share a hash, and each would read the other's streams out of the dispatcher's view and
    /// deliver its own signed events to the other's receivers.
    /// </summary>
    [Fact]
    public async Task AnotherTransmittersRegistry_IsNotVisible()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore();
        var other = new RedisStreamStore(
            garnet.Connection,
            new SharedSignalsTransmitterOptions { Issuer = "https://other-transmitter.example.com" });

        var mine = Guid.NewGuid().ToString("N");
        var theirs = Guid.NewGuid().ToString("N");
        Assert.True(await store.TryCreateAsync(NewState(mine), ct));
        Assert.True(await other.TryCreateAsync(NewState(theirs), ct));

        try
        {
            Assert.DoesNotContain(await store.ListAllAsync(ct), stream => stream.StreamId == theirs);
            Assert.DoesNotContain(await other.ListAllAsync(ct), stream => stream.StreamId == mine);
            Assert.Null(await store.FindAsync(_receiver, theirs, ct));
        }
        finally
        {
            await other.DeleteAsync(_receiver, theirs, ct);
        }
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
        before.AddSingleton(Options);
        before.AddSharedSignalsRedisStreamStore();
        before.TryAddSingleton<IStreamStore, InMemoryStreamStore>();
        Assert.IsType<RedisStreamStore>(
            before.BuildServiceProvider().GetRequiredService<IStreamStore>());

        var after = new ServiceCollection();
        after.AddSingleton<StackExchange.Redis.IConnectionMultiplexer>(garnet.Connection);
        after.AddSingleton(Options);
        after.TryAddSingleton<IStreamStore, InMemoryStreamStore>();
        after.AddSharedSignalsRedisStreamStore();
        Assert.IsType<RedisStreamStore>(
            after.BuildServiceProvider().GetRequiredService<IStreamStore>());
    }
}
