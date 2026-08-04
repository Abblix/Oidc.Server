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

using System.Net;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the transmitter's management semantics per SSF 1.0 Section 8.1: what a create supplies
/// and refuses, what PATCH leaves alone and PUT deletes, how status changes treat the held
/// queue, the anti-probing posture of the subject endpoints, and the verification throttle.
/// </summary>
public class StreamManagementServiceTests
{
    private const string Receiver = "receiver-a";
    private const string TypeA = "https://example.com/events/type-a";
    private const string TypeB = "https://example.com/events/type-b";

    private sealed class StubSigner : ISecurityEventTokenSigner
    {
        public List<SecurityEventToken> Signed { get; } = [];

        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        {
            Signed.Add(token);
            return Task.FromResult($"signed.{token.JwtId}");
        }
    }

    private sealed record Harness(
        StreamManagementService Service,
        InMemoryStreamStore Store,
        InMemoryEventOutbox Outbox,
        StubSigner Signer,
        FakeTimeProvider Clock);

    private static Harness CreateHarness() => CreateHarness(new SsfTransmitterOptions
    {
        Issuer = "https://tr.example.com",
        EventsSupported = [TypeA, TypeB],
        PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
        MinVerificationInterval = TimeSpan.FromMinutes(5),
    });

    private static Harness CreateHarness(SsfTransmitterOptions options)
    {
        var store = new InMemoryStreamStore();
        var outbox = new InMemoryEventOutbox();
        var signer = new StubSigner();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754200000));
        var dispatcher = new EventDispatcher(store, outbox, signer, options.Issuer, clock: clock);

        return new Harness(
            new StreamManagementService(store, outbox, dispatcher, options, clock),
            store, outbox, signer, clock);
    }

    private static async Task<StreamConfiguration> CreatedStreamAsync(
        Harness harness,
        CreateStreamRequest? request = null)
    {
        var created = await harness.Service.CreateStreamAsync(
            Receiver,
            request ?? new CreateStreamRequest { EventsRequested = [TypeA] },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return created.Body!;
    }

    [Fact]
    public async Task Create_SuppliesTheTransmitterHalf_AndDefaultsToPoll()
    {
        var harness = CreateHarness();

        var configuration = await CreatedStreamAsync(harness, new CreateStreamRequest
        {
            // TypeB is requested but the receiver also asks for something unsupported, which
            // the transmitter ignores (Section 8.1.1): delivered = supported ∩ requested.
            EventsRequested = [TypeB, "https://example.com/events/unknown"],
            Description = "Stream for Receiver A",
        });

        Assert.Equal("https://tr.example.com", configuration.Issuer);
        Assert.Equal([Receiver], configuration.Audiences);
        Assert.Equal([TypeB], configuration.EventsDelivered);
        Assert.Equal("Stream for Receiver A", configuration.Description);

        // No delivery proposed means poll, with the endpoint URL the transmitter's own
        // (Section 8.1.1.1).
        var poll = Assert.IsType<PollDeliveryMethod>(configuration.Delivery);
        Assert.Equal(
            new Uri($"https://tr.example.com/ssf/poll/{configuration.StreamId}"),
            poll.EndpointUrl);
    }

    [Fact]
    public async Task Create_SecondStream_ConflictsUnderTheSingleStreamPolicy()
    {
        var harness = CreateHarness();
        await CreatedStreamAsync(harness);

        var second = await harness.Service.CreateStreamAsync(
            Receiver, new CreateStreamRequest(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Create_PollAskedOfAPushOnlyTransmitter_IsRefused()
    {
        var harness = CreateHarness(new SsfTransmitterOptions
        {
            Issuer = "https://tr.example.com",
            EventsSupported = [TypeA],
        });

        var result = await harness.Service.CreateStreamAsync(
            Receiver, new CreateStreamRequest(), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, result.StatusCode);
    }

    [Fact]
    public async Task Update_ChangesOnlyWhatWasSent()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness, new CreateStreamRequest
        {
            EventsRequested = [TypeA],
            Description = "original",
        });

        var updated = await harness.Service.UpdateStreamAsync(
            Receiver,
            new UpdateStreamRequest { StreamId = created.StreamId, EventsRequested = [TypeB] },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal([TypeB], updated.Body!.EventsDelivered);
        // The description was absent from the PATCH, so it stays (Section 8.1.1.3).
        Assert.Equal("original", updated.Body.Description);
    }

    [Fact]
    public async Task Replace_DeletesTheAbsent_AndRefusesToDeleteTheDelivery()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness, new CreateStreamRequest
        {
            EventsRequested = [TypeA],
            Description = "original",
        });

        var replaced = await harness.Service.ReplaceStreamAsync(
            Receiver,
            new UpdateStreamRequest
            {
                StreamId = created.StreamId,
                Delivery = new PollDeliveryMethod(),
                EventsRequested = [TypeA],
            },
            TestContext.Current.CancellationToken);

        // The description was absent from the PUT body: deleted (Section 8.1.1.4).
        Assert.Equal(HttpStatusCode.OK, replaced.StatusCode);
        Assert.Null(replaced.Body!.Description);

        var withoutDelivery = await harness.Service.ReplaceStreamAsync(
            Receiver,
            new UpdateStreamRequest { StreamId = created.StreamId },
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, withoutDelivery.StatusCode);
    }

    [Fact]
    public async Task Delete_DropsTheStreamAndItsQueue()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);
        await harness.Outbox.EnqueueAsync(
            created.StreamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

        var deleted = await harness.Service.DeleteStreamAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.Empty(await harness.Outbox.PendingAsync(
            created.StreamId, null, TestContext.Current.CancellationToken));
        Assert.Equal(
            HttpStatusCode.NotFound,
            (await harness.Service.DeleteStreamAsync(
                Receiver, created.StreamId, TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task StatusUpdate_ValidatesTheValue_AndDisablingDropsTheHeldQueue()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);
        await harness.Outbox.EnqueueAsync(
            created.StreamId, new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

        var invalid = await harness.Service.UpdateStreamStatusAsync(
            Receiver,
            new StreamStatus { StreamId = created.StreamId, Status = "hibernating" },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);

        var disabled = await harness.Service.UpdateStreamStatusAsync(
            Receiver,
            new StreamStatus { StreamId = created.StreamId, Status = StreamStatuses.Disabled },
            TestContext.Current.CancellationToken);

        // "will not hold any events for later transmission" (Section 8.1.2.1).
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        Assert.Equal(StreamStatuses.Disabled, disabled.Body!.Status);
        Assert.Empty(await harness.Outbox.PendingAsync(
            created.StreamId, null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Subjects_AdditionCovers_AndRemovalAnswersSuccessEvenForTheNeverAdded()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);
        var subject = new EmailSubject("jdoe@example.com");

        var addition = await harness.Service.AddSubjectAsync(
            Receiver,
            new AddSubjectRequest { StreamId = created.StreamId, Subject = subject },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, addition.StatusCode);

        var state = await harness.Store.FindAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);
        var added = Assert.Single(state!.AddedSubjects);
        Assert.True(added.Verified);

        // Removing a subject nobody added still answers success: a 404 here is the probing
        // signal Section 9.1 warns about.
        var removal = await harness.Service.RemoveSubjectAsync(
            Receiver,
            new RemoveSubjectRequest
            {
                StreamId = created.StreamId,
                Subject = new EmailSubject("stranger@example.com"),
            },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, removal.StatusCode);
    }

    [Fact]
    public async Task AllMode_RemovalCarvesOut_AndReAdditionRestores()
    {
        var harness = CreateHarness(new SsfTransmitterOptions
        {
            Issuer = "https://tr.example.com",
            EventsSupported = [TypeA],
            DefaultSubjectsMode = StreamSubjectsMode.All,
            PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
        });
        var created = await CreatedStreamAsync(harness);
        var subject = new EmailSubject("optout@example.com");

        await harness.Service.RemoveSubjectAsync(
            Receiver,
            new RemoveSubjectRequest { StreamId = created.StreamId, Subject = subject },
            TestContext.Current.CancellationToken);

        var carved = await harness.Store.FindAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);
        Assert.Single(carved!.RemovedSubjects);

        await harness.Service.AddSubjectAsync(
            Receiver,
            new AddSubjectRequest { StreamId = created.StreamId, Subject = subject },
            TestContext.Current.CancellationToken);

        var restored = await harness.Store.FindAsync(
            Receiver, created.StreamId, TestContext.Current.CancellationToken);
        Assert.Empty(restored!.RemovedSubjects);
    }

    [Fact]
    public async Task Verification_EnqueuesTheStreamsOwnEvent_AndThrottlesInsideTheInterval()
    {
        var harness = CreateHarness();
        var created = await CreatedStreamAsync(harness);

        var first = await harness.Service.RequestVerificationAsync(
            Receiver,
            new VerificationRequest { StreamId = created.StreamId, State = "opaque-state" },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);

        // The SET's subject is the stream itself, opaque (Section 8.1.4.1), and the state is
        // echoed in the event payload.
        var minted = Assert.Single(harness.Signer.Signed);
        Assert.Equal(created.StreamId, Assert.IsType<OpaqueSubject>(minted.GetSubjectId()).Id);
        Assert.Single(await harness.Outbox.PendingAsync(
            created.StreamId, null, TestContext.Current.CancellationToken));

        var throttled = await harness.Service.RequestVerificationAsync(
            Receiver,
            new VerificationRequest { StreamId = created.StreamId },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.TooManyRequests, throttled.StatusCode);

        harness.Clock.Advance(TimeSpan.FromMinutes(6));
        var afterInterval = await harness.Service.RequestVerificationAsync(
            Receiver,
            new VerificationRequest { StreamId = created.StreamId },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NoContent, afterInterval.StatusCode);
    }
}
