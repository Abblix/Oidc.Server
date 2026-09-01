// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging.Abstractions;
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
        public Task<bool> IsSharingPermittedAsync(
            StreamState stream,
            SecurityEventDescriptor descriptor,
            CancellationToken cancellationToken = default)
            => Task.FromResult(false);
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
        return (new EventDispatcher(NullLogger<EventDispatcher>.Instance, store, outbox, signer, Issuer, policy), outbox, signer);
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
        var item = Assert.Single(await outbox.PendingAsync("receiver-a", "s-1", null, TestContext.Current.CancellationToken));
        Assert.Equal($"signed.{item.JwtId}", item.CompactToken);

        var minted = Assert.Single(signer.Signed);
        Assert.Equal(Issuer, minted.Issuer);
        Assert.Equal(["https://receiver.example.com/s-1"], minted.Audiences);
        Assert.Equal("jdoe@example.com", Assert.IsType<EmailSubject>(minted.GetSubjectId()).Email);
        Assert.NotNull(minted.Events);
        Assert.True(minted.Events.TryGetPayload(MembershipChanged, out _));
    }

    /// <summary>
    /// A stream nobody added a subject to: everything under <c>All</c>, nothing under <c>None</c>.
    /// </summary>
    /// <remarks>
    /// The pair is what a conformant receiver meets. The CAEP Interoperability Profile 1.0 Section 2.4.4
    /// tells it to "assume that all subjects are implicitly included in a Stream, without any Add Subject
    /// method invocations", so it adds none - and against a transmitter whose new streams cover nothing it
    /// receives nothing, with no error on either side. What each row uniquely holds is the EMPTY list on
    /// its own side, measured rather than asserted: narrowing <c>None</c> to also cover a stream with no
    /// added subjects kills this row alone out of the suite, and widening <c>All</c> to require a
    /// non-empty removed list kills the other alone.
    /// </remarks>
    [Theory]
    [InlineData(StreamSubjectsMode.All, 1)]
    [InlineData(StreamSubjectsMode.None, 0)]
    public async Task AStreamWithNoAddedSubjects_DeliversByItsMode(StreamSubjectsMode mode, int expected)
    {
        var subject = new EmailSubject("jdoe@example.com");
        var (dispatcher, outbox, _) = await CreateDispatcherAsync(
            policy: null,
            CreateStream("s-1", mode: mode));

        var reached = await dispatcher.DispatchAsync(
            Descriptor(subject), TestContext.Current.CancellationToken);

        Assert.Equal(expected, reached);
        Assert.Equal(
            expected,
            (await outbox.PendingAsync("receiver-a", "s-1", null, TestContext.Current.CancellationToken)).Count);
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
        Assert.Empty(await outbox.PendingAsync("receiver-a", "other-type", null, TestContext.Current.CancellationToken));
        Assert.Empty(await outbox.PendingAsync("receiver-a", "other-subject", null, TestContext.Current.CancellationToken));
        Assert.Empty(await outbox.PendingAsync("receiver-a", "disabled", null, TestContext.Current.CancellationToken));
        Assert.Single(await outbox.PendingAsync("receiver-a", "paused", null, TestContext.Current.CancellationToken));
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

        Assert.Single(await outbox.PendingAsync("receiver-a", "s-all", null, TestContext.Current.CancellationToken));
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
        Assert.Empty(await outbox.PendingAsync("receiver-a", "s-1", null, TestContext.Current.CancellationToken));
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
                EventType = Events.SharedSignalsEventTypes.StreamUpdated,
                Subject = new OpaqueSubject("s-1"),
                Payload = new Events.StreamUpdatedEventPayload { Status = StreamStatuses.Disabled },
            },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Single(await outbox.PendingAsync("receiver-a", "s-1", null, TestContext.Current.CancellationToken));
        var minted = Assert.Single(signer.Signed);
        Assert.Equal("s-1", Assert.IsType<OpaqueSubject>(minted.GetSubjectId()).Id);
    }
}
