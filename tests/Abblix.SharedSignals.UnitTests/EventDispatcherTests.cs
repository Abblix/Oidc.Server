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

using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the dispatcher's fan-out: which streams an event reaches - status, delivered types,
/// subject coverage (SSF 1.0 Section 8.1.3.1) and the sharing policy (Section 9.2), in that
/// order - and what the per-stream SET carries.
/// </summary>
public class EventDispatcherTests
{
    private const string Issuer = "https://tr.example.com";
    private const string MembershipChanged = "https://example.com/events/membership-changed";

    /// <summary>
    /// A signer that records what it was asked to sign and returns an inspectable stand-in:
    /// the dispatcher's contract is what it MINTS, and cryptography has its own tests.
    /// </summary>
    private sealed class CapturingSigner : ISecurityEventTokenSigner
    {
        public List<SecurityEventToken> Signed { get; } = [];

        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        {
            Signed.Add(token);
            return Task.FromResult($"signed.{token.JwtId}");
        }
    }

    private sealed class DenyAllPolicy : IEventSharingPolicy
    {
        public ValueTask<bool> IsSharingPermittedAsync(
            StreamState stream,
            SecurityEventDescriptor descriptor,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(false);
    }

    private static StreamState CreateStream(
        string streamId,
        string status = StreamStatuses.Enabled,
        StreamSubjectsMode mode = StreamSubjectsMode.None,
        IReadOnlyList<StreamSubject>? added = null,
        IReadOnlyList<SubjectIdentifier>? removed = null,
        IReadOnlyList<string>? delivered = null) => new()
    {
        ReceiverId = "receiver-a",
        Status = status,
        SubjectsMode = mode,
        AddedSubjects = added ?? [],
        RemovedSubjects = removed ?? [],
        Configuration = new StreamConfiguration
        {
            StreamId = streamId,
            Issuer = Issuer,
            Audiences = [$"https://receiver.example.com/{streamId}"],
            EventsDelivered = delivered ?? [MembershipChanged],
            Delivery = new PollDeliveryMethod(new Uri($"https://tr.example.com/poll/{streamId}")),
        },
    };

    private static SecurityEventDescriptor Descriptor(SubjectIdentifier? subject = null) => new()
    {
        EventType = MembershipChanged,
        Subject = subject ?? new EmailSubject("jdoe@example.com"),
    };

    private static async Task<(EventDispatcher Dispatcher, InMemoryEventOutbox Outbox, CapturingSigner Signer)>
        CreateDispatcherAsync(IEventSharingPolicy? policy, params StreamState[] streams)
    {
        var store = new InMemoryStreamStore();
        foreach (var stream in streams)
        {
            Assert.True(await store.TryCreateAsync(stream, TestContext.Current.CancellationToken));
        }

        var outbox = new InMemoryEventOutbox();
        var signer = new CapturingSigner();
        return (new EventDispatcher(store, outbox, signer, Issuer, policy), outbox, signer);
    }

    [Fact]
    public async Task Dispatch_ReachesTheMatchingStream_AndMintsItsOwnSet()
    {
        var subject = new EmailSubject("jdoe@example.com");
        var (dispatcher, outbox, signer) = await CreateDispatcherAsync(
            policy: null,
            CreateStream("s-1", added: [new StreamSubject(subject, Verified: true)]));

        var reached = await dispatcher.DispatchAsync(
            Descriptor(subject), TestContext.Current.CancellationToken);

        Assert.Equal(1, reached);
        var item = Assert.Single(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.Equal($"signed.{item.JwtId}", item.CompactToken);

        var minted = Assert.Single(signer.Signed);
        Assert.Equal(Issuer, minted.Issuer);
        Assert.Equal(["https://receiver.example.com/s-1"], minted.Audiences);
        Assert.Equal("jdoe@example.com", Assert.IsType<EmailSubject>(minted.GetSubjectId()).Email);
        Assert.NotNull(minted.Events);
        Assert.True(minted.Events.TryGetPayload(MembershipChanged, out _));
    }

    [Fact]
    public async Task Dispatch_SkipsWhatDoesNotMatch()
    {
        var subject = new EmailSubject("jdoe@example.com");
        var covering = new StreamSubject(subject, Verified: true);
        var (dispatcher, outbox, _) = await CreateDispatcherAsync(
            policy: null,
            CreateStream("other-type", added: [covering], delivered: ["https://example.com/events/other"]),
            CreateStream("other-subject", added: [new StreamSubject(new EmailSubject("else@example.com"), true)]),
            CreateStream("disabled", status: StreamStatuses.Disabled, added: [covering]),
            CreateStream("paused", status: StreamStatuses.Paused, added: [covering]));

        var reached = await dispatcher.DispatchAsync(
            Descriptor(subject), TestContext.Current.CancellationToken);

        // Of the four, only the paused stream takes the event: pausing HOLDS events for later
        // (SSF 1.0 Section 8.1.2.1), and the hold is the outbox nobody drains.
        Assert.Equal(1, reached);
        Assert.Empty(await outbox.PendingAsync("other-type", null, TestContext.Current.CancellationToken));
        Assert.Empty(await outbox.PendingAsync("other-subject", null, TestContext.Current.CancellationToken));
        Assert.Empty(await outbox.PendingAsync("disabled", null, TestContext.Current.CancellationToken));
        Assert.Single(await outbox.PendingAsync("paused", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AllMode_CoversEverything_ExceptTheRemoved()
    {
        var removed = new EmailSubject("optout@example.com");
        var (dispatcher, outbox, _) = await CreateDispatcherAsync(
            policy: null,
            CreateStream("s-all", mode: StreamSubjectsMode.All, removed: [removed]));

        Assert.Equal(1, await dispatcher.DispatchAsync(
            Descriptor(new EmailSubject("anyone@example.com")), TestContext.Current.CancellationToken));
        Assert.Equal(0, await dispatcher.DispatchAsync(
            Descriptor(removed), TestContext.Current.CancellationToken));

        Assert.Single(await outbox.PendingAsync("s-all", null, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task SharingPolicy_VetoesAnOtherwiseMatchingDelivery()
    {
        // Section 9.2: an added subject is interest, not entitlement - the policy's silent "no"
        // must leave nothing behind that a receiver could observe.
        var subject = new EmailSubject("jdoe@example.com");
        var (dispatcher, outbox, signer) = await CreateDispatcherAsync(
            new DenyAllPolicy(),
            CreateStream("s-1", added: [new StreamSubject(subject, Verified: true)]));

        Assert.Equal(0, await dispatcher.DispatchAsync(
            Descriptor(subject), TestContext.Current.CancellationToken));
        Assert.Empty(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        Assert.Empty(signer.Signed);
    }

    [Fact]
    public async Task TargetedDispatch_IgnoresMatching_ForTheFrameworksOwnSignals()
    {
        // A stream-updated event precedes the stop and may be absent from events_delivered
        // (SSF 1.0 Sections 8.1.4, 8.1.5), so the targeted door skips every matching check.
        var stream = CreateStream("s-1", status: StreamStatuses.Disabled, delivered: []);
        var (dispatcher, outbox, signer) = await CreateDispatcherAsync(policy: null, stream);

        await dispatcher.DispatchToStreamAsync(
            stream,
            new SecurityEventDescriptor
            {
                EventType = Events.SsfEventTypes.StreamUpdated,
                Subject = new OpaqueSubject("s-1"),
                Payload = new Events.StreamUpdatedEventPayload { Status = StreamStatuses.Disabled },
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Single(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
        var minted = Assert.Single(signer.Signed);
        Assert.Equal("s-1", Assert.IsType<OpaqueSubject>(minted.GetSubjectId()).Id);
    }
}
