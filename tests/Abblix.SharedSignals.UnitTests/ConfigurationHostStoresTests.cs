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

using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Subjects;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the two host-store choices of a closed deployment: the stream set as configuration -
/// materialized like the dynamic create would, refusing configuration bugs loudly at startup -
/// and the outbox on the distributed cache, whose queues survive a process restart when the
/// store behind the cache does.
/// </summary>
public class ConfigurationHostStoresTests
{
    private const string TypeA = "https://example.com/events/type-a";

    private static SsfTransmitterOptions TransmitterOptions => new()
    {
        Issuer = "https://tr.example.com",
        EventsSupported = [TypeA],
        PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
    };

    [Fact]
    public async Task ConfiguredStreams_MaterializeAsTheDynamicCreateWould()
    {
        var store = new ConfigurationStreamStore(TransmitterOptions,
        [
            new ConfiguredStream
            {
                ReceiverId = "kezio",
                StreamId = "kezio-main",
                EventsRequested = [TypeA, "https://example.com/events/unsupported"],
                PushEndpointUrl = new Uri("https://kezio.example.com/events"),
                PushAuthorizationHeader = "Bearer from-secret",
            },
            new ConfiguredStream { ReceiverId = "admin", StreamId = "admin-main" },
        ], new InMemoryStreamStore());

        var kezio = await store.FindAsync("kezio", "kezio-main", TestContext.Current.CancellationToken);
        Assert.NotNull(kezio);
        Assert.Equal(StreamSubjectsMode.All, kezio.SubjectsMode);
        Assert.Equal(["kezio"], kezio.Configuration.Audiences);
        Assert.Equal([TypeA], kezio.Configuration.EventsDelivered);
        var push = Assert.IsType<PushDeliveryMethod>(kezio.Configuration.Delivery);
        Assert.Equal("Bearer from-secret", push.AuthorizationHeader);

        // No push endpoint declared means poll over the transmitter's own URL.
        var admin = await store.FindAsync("admin", "admin-main", TestContext.Current.CancellationToken);
        var poll = Assert.IsType<PollDeliveryMethod>(admin!.Configuration.Delivery);
        Assert.Equal(new Uri("https://tr.example.com/ssf/poll/admin-main"), poll.EndpointUrl);

        Assert.Equal(2, (await store.ListAllAsync(TestContext.Current.CancellationToken)).Count);
    }

    [Fact]
    public async Task ConfiguredStreams_AcceptEphemeralMutation_TheVerificationThrottleNeedsIt()
    {
        var store = new ConfigurationStreamStore(TransmitterOptions,
            [new ConfiguredStream { ReceiverId = "kezio", StreamId = "kezio-main" }],
            new InMemoryStreamStore());

        var stream = await store.FindAsync("kezio", "kezio-main", TestContext.Current.CancellationToken);
        Assert.True(await store.UpdateAsync(
            stream! with { Status = StreamStatuses.Paused },
            TestContext.Current.CancellationToken));

        Assert.Equal(
            StreamStatuses.Paused,
            (await store.FindAsync("kezio", "kezio-main", TestContext.Current.CancellationToken))!.Status);
    }

    /// <summary>
    /// The reconcile's whole point: what a RECEIVER did through the management API survives a
    /// restart, and is therefore visible to a second instance over the same backing store rather
    /// than living in the memory of whichever one took the request.
    /// </summary>
    /// <remarks>
    /// The subject half matters more than the status half and is easier to lose. Under
    /// SubjectsMode.None the added subjects ARE the stream's coverage, so rebuilding the state
    /// from the file would unsubscribe the receiver from everything it subscribed to - and SSF 1.0
    /// Section 9.1 tells that receiver a success says nothing about the transmitter's state, so it
    /// never asks and never learns.
    /// </remarks>
    [Fact]
    public async Task WhatTheReceiverOwns_SurvivesAReconcile()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var shared = new InMemoryStreamStore();
        ConfiguredStream[] declared =
            [new ConfiguredStream { ReceiverId = "kezio", StreamId = "kezio-main", SubjectsMode = StreamSubjectsMode.None }];

        var first = new ConfigurationStreamStore(TransmitterOptions, declared, shared);
        var stream = await first.FindAsync("kezio", "kezio-main", cancellationToken);
        Assert.True(await first.UpdateAsync(
            stream! with
            {
                Status = StreamStatuses.Paused,
                StatusReason = "under investigation",
                AddedSubjects = [new StreamSubject(new OpaqueSubject("user-1"), true)],
            },
            cancellationToken));

        // A second instance over the same backing store: a restart, or the replica beside it.
        var second = new ConfigurationStreamStore(TransmitterOptions, declared, shared);
        var reconciled = await second.FindAsync("kezio", "kezio-main", cancellationToken);

        Assert.NotNull(reconciled);
        Assert.Equal(StreamStatuses.Paused, reconciled.Status);
        Assert.Equal("under investigation", reconciled.StatusReason);
        var subject = Assert.Single(reconciled.AddedSubjects);
        Assert.Equal("user-1", Assert.IsType<OpaqueSubject>(subject.Subject).Id);
    }

    /// <summary>
    /// The other half of the same split: what the FILE owns is written over whatever the backing
    /// store holds, so editing configuration reaches a deployment at its next start instead of
    /// being refused because the stream already exists.
    /// </summary>
    [Fact]
    public async Task WhatTheFileOwns_IsRewrittenByAReconcile()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var shared = new InMemoryStreamStore();

        var before = new ConfigurationStreamStore(
            TransmitterOptions,
            [new ConfiguredStream
            {
                ReceiverId = "kezio",
                StreamId = "kezio-main",
                PushEndpointUrl = new Uri("https://kezio.example.com/old"),
            }],
            shared);

        var stream = await before.FindAsync("kezio", "kezio-main", cancellationToken);
        Assert.True(await before.UpdateAsync(
            stream! with { Status = StreamStatuses.Paused }, cancellationToken));

        // The operator edits the file and the deployment restarts.
        var after = new ConfigurationStreamStore(
            TransmitterOptions,
            [new ConfiguredStream
            {
                ReceiverId = "kezio",
                StreamId = "kezio-main",
                PushEndpointUrl = new Uri("https://kezio.example.com/new"),
            }],
            shared);

        var reconciled = await after.FindAsync("kezio", "kezio-main", cancellationToken);
        var push = Assert.IsType<PushDeliveryMethod>(reconciled!.Configuration.Delivery);
        Assert.Equal(new Uri("https://kezio.example.com/new"), push.EndpointUrl);

        // And the edit did not cost the receiver its half.
        Assert.Equal(StreamStatuses.Paused, reconciled.Status);
    }

    /// <summary>
    /// A stream the file no longer declares is dropped, because in this store the file IS the
    /// stream set. Keeping it would go on delivering security events to a receiver the operator
    /// removed, which is the failure that matters of the two directions.
    /// </summary>
    [Fact]
    public async Task AStreamTheFileNoLongerDeclares_IsDropped()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var shared = new InMemoryStreamStore();

        var before = new ConfigurationStreamStore(
            TransmitterOptions,
            [
                new ConfiguredStream { ReceiverId = "kezio", StreamId = "kezio-main" },
                new ConfiguredStream { ReceiverId = "departed", StreamId = "departed-main" },
            ],
            shared);
        Assert.Equal(2, (await before.ListAllAsync(cancellationToken)).Count);

        var after = new ConfigurationStreamStore(
            TransmitterOptions,
            [new ConfiguredStream { ReceiverId = "kezio", StreamId = "kezio-main" }],
            shared);

        var remaining = Assert.Single(await after.ListAllAsync(cancellationToken));
        Assert.Equal("kezio", remaining.ReceiverId);
        Assert.Null(await after.FindAsync("departed", "departed-main", cancellationToken));
    }

    [Fact]
    public void ConfigurationBugs_RefuseLoudlyAtStartup()
    {
        // A duplicate declaration and an undeliverable stream are operator mistakes; surfacing
        // them at construction beats a stream that silently cannot flow.
        var duplicate = Assert.Throws<InvalidOperationException>(() => new ConfigurationStreamStore(
            TransmitterOptions,
            [
                new ConfiguredStream { ReceiverId = "kezio", StreamId = "s-1" },
                new ConfiguredStream { ReceiverId = "kezio", StreamId = "s-1" },
            ], new InMemoryStreamStore()));
        Assert.Contains("more than once", duplicate.Message);

        var undeliverable = Assert.Throws<InvalidOperationException>(() => new ConfigurationStreamStore(
            new SsfTransmitterOptions { Issuer = "https://tr.example.com" },
            [new ConfiguredStream { ReceiverId = "kezio", StreamId = "s-1" }],
            new InMemoryStreamStore()));
        Assert.Contains(nameof(ConfiguredStream.PushEndpointUrl), undeliverable.Message);
    }

    [Fact]
    public async Task DistributedOutbox_KeepsTheQueueInTheCache_AcrossAProcessRestart()
    {
        // Two outbox instances over ONE cache stand in for the process before and after a
        // restart: what the first enqueued, the second still serves - the queue's home is the
        // cache, not the object.
        var sharedCache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

        using (var before = new DistributedCacheEventOutbox(sharedCache))
        {
            await before.EnqueueAsync(
                "s-1", new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);
            await before.EnqueueAsync(
                "s-1", new OutboxItem("jti-2", "b.b.b"), TestContext.Current.CancellationToken);
        }

        using var after = new DistributedCacheEventOutbox(sharedCache);
        Assert.Equal(
            ["jti-1", "jti-2"],
            (await after.PendingAsync("s-1", null, TestContext.Current.CancellationToken))
            .Select(item => item.JwtId));

        await after.AcknowledgeAsync("s-1", ["jti-1"], TestContext.Current.CancellationToken);
        var remaining = Assert.Single(
            await after.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.Equal("jti-2", remaining.JwtId);

        await after.ClearAsync("s-1", TestContext.Current.CancellationToken);
        Assert.Empty(await after.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ExplicitStoreChoices_Win_WhicheverSideOfTheRoleRegistrationTheyLand()
    {
        // The conveniences are the host's explicit choice, so unlike the TryAdd defaults they
        // must win even AFTER AddSsfTransmitter has registered the in-memory pair.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISecurityEventTokenSigner, FakeSigner>();
        services.AddSecurityEvents();
        services.AddDistributedMemoryCache();

        services
            .AddSsfTransmitter(TransmitterOptions)
            .AddSsfConfiguredStreams([new ConfiguredStream { ReceiverId = "kezio", StreamId = "s-1" }])
            .AddSsfDistributedOutbox();

        using var provider = services.BuildServiceProvider();
        Assert.IsType<ConfigurationStreamStore>(provider.GetRequiredService<IStreamStore>());
        Assert.IsType<DistributedCacheEventOutbox>(provider.GetRequiredService<IEventOutbox>());
    }

    private sealed class FakeSigner : ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(
            Abblix.SecurityEvents.SecurityEventToken token,
            CancellationToken cancellationToken = default)
            => Task.FromResult($"signed.{token.JwtId}");
    }
}
