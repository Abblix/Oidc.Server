// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.CAEP;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// The CAEP Interoperability Profile's demand on a transmitter, driven through the dispatcher with the
/// real policy rather than a stand-in, because the two live in packages that do not reference each other.
/// </summary>
/// <remarks>
/// Section 3 of the profile opens "An implementation conforming to this profile MUST support at least one
/// of the following use cases", and each of the three demands the same member: 3.1 "The reason_admin field
/// of the event MUST be populated with a non-empty object", 3.2 and 3.3 "Transmitters MUST populate this
/// value with a non-empty object". All three land on the TRANSMITTER; nothing obliges a receiver to reject
/// an event without it, which is why the payload type stays permissive.
/// </remarks>
public sealed class CaepInteropProfileDispatchTests
{
    private const string Issuer = "https://tr.example.com";

    /// <summary>
    /// Each of the three use cases, because a policy that recognised only <c>session-revoked</c> would
    /// pass a suite written for the event the specification happens to name first.
    /// </summary>
    [Theory]
    [InlineData(CaepEventTypes.SessionRevoked)]
    [InlineData(CaepEventTypes.CredentialChange)]
    [InlineData(CaepEventTypes.DeviceComplianceChange)]
    public async Task AnEventWithNoReasonAdmin_IsRefused(string eventType)
    {
        var (dispatcher, outbox, _) = await CreateAsync(eventType, new CaepInteropProfilePolicy());

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => dispatcher.DispatchAsync(Descriptor(eventType, PayloadFor(eventType)), Cancellation));

        Assert.Contains(eventType, refusal.Message);

        // The distinguishing phrase, not merely the member's name: the "cannot be read" refusal carries
        // the event type and the member too, so a row asserting those alone passes when a CAEP payload
        // falls through to the wrong arm.
        Assert.Contains("not a non-empty object", refusal.Message);
        Assert.Empty(await outbox.PendingAsync("s-1", null, Cancellation));
    }

    /// <summary>
    /// An empty object is its own row. <c>{}</c> deserializes to a non-null empty dictionary and is emitted
    /// as <c>"reason_admin": {}</c>, so a check testing only for absence would let it through - and the
    /// specification says non-empty, not present.
    /// </summary>
    [Fact]
    public async Task AnEventWhoseReasonAdminIsEmpty_IsRefused()
    {
        var (dispatcher, _, _) = await CreateAsync(CaepEventTypes.SessionRevoked, new CaepInteropProfilePolicy());

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => dispatcher.DispatchAsync(
                Descriptor(
                    CaepEventTypes.SessionRevoked,
                    new SessionRevokedPayload { ReasonAdmin = new Dictionary<string, string>() }),
                Cancellation));

        Assert.Contains("not a non-empty object", refusal.Message);
    }

    /// <summary>
    /// An event carrying no payload at all is refused, which is the shape the issue was filed on.
    /// </summary>
    /// <remarks>
    /// <c>SecurityEventDescriptor.Payload</c> is nullable and the builder has a branch for it, so a host
    /// emitting <c>session-revoked</c> with nothing attached is emitting exactly the non-conformant event
    /// this policy exists to stop - and every other refusing row here passes a payload.
    /// </remarks>
    [Fact]
    public async Task AnEventWithNoPayloadAtAll_IsRefused()
    {
        var (dispatcher, outbox, _) = await CreateAsync(
            CaepEventTypes.SessionRevoked, new CaepInteropProfilePolicy());

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => dispatcher.DispatchAsync(
                new SecurityEventDescriptor
                {
                    EventType = CaepEventTypes.SessionRevoked,
                    Subject = new EmailSubject("jdoe@example.com"),
                },
                Cancellation));

        // The distinguishing phrase. Without it the row passes when the null arm is deleted and the event
        // falls through to "a payload of type '' cannot be read" - a sentence naming a type that is not
        // there, for an event that simply carries nothing.
        Assert.Contains("not a non-empty object", refusal.Message);
        Assert.Empty(await outbox.PendingAsync("s-1", null, Cancellation));
    }

    /// <summary>
    /// A member that is present and non-empty but not an object is refused for what it IS, not for being
    /// absent.
    /// </summary>
    /// <remarks>
    /// Reachable only through the relayed arm, since a wrongly typed member on a typed payload fails at
    /// deserialization. Saying "absent or empty" of a member sitting right there sends a host debugging
    /// its relay upstream to look for something that is not missing.
    /// </remarks>
    [Theory]
    [InlineData("\"a message\"")]
    [InlineData("[\"en\"]")]
    [InlineData("0")]
    public async Task ARelayedMemberOfTheWrongKind_IsRefusedForWhatItIs(string rawValue)
    {
        var json = new JsonObject
        {
            [CaepClaimNames.ReasonAdmin] = JsonNode.Parse(rawValue),
        };
        var (dispatcher, _, _) = await CreateAsync(
            CaepEventTypes.SessionRevoked, new CaepInteropProfilePolicy());

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => dispatcher.DispatchAsync(
                Descriptor(CaepEventTypes.SessionRevoked, new UnknownEventPayload(json)), Cancellation));

        Assert.Contains("not a non-empty object", refusal.Message);
        Assert.DoesNotContain("absent", refusal.Message);
    }

    /// <summary>
    /// A claimed use case the profile does not define is refused at construction, not at dispatch.
    /// </summary>
    /// <remarks>
    /// Left unchecked, it would produce a policy that is registered, resolvable, consulted on every event
    /// and refuses nothing - the quietly non-conformant transmitter this class exists to prevent, reached
    /// by a typo or by the profile's own prose, which names its use cases <c>session-revoked</c> rather
    /// than by event type URI. That value is the row.
    /// </remarks>
    [Theory]
    [InlineData("session-revoked")]
    [InlineData("sesion-revoked")]
    [InlineData(null)]
    [InlineData("")]
    public void AClaimedUseCaseTheProfileDoesNotDefine_IsRefusedAtConstruction(string? claimed)
    {
        // The array is what a configuration binder produces, so a null element is a shape a host reaches
        // without writing one: a JSON array carrying a null, or a missing key read into the array. It sat
        // in the first position deliberately - a search that returns the offending ELEMENT cannot tell a
        // null it found from nothing at all, so a null here used to silence the guard for everything
        // after it.
        var refusal = Assert.Throws<ArgumentException>(
            () => new CaepInteropProfilePolicy(claimed!, "sesion-change"));

        // The value, not merely the list of valid ones - which the same message prints, so asserting a
        // valid URI passes with the offending value dropped from the sentence entirely.
        Assert.Contains(claimed is null ? "<null>" : $"'{claimed}'", refusal.Message);
    }

    /// <summary>
    /// A null ahead of a real typo does not swallow it: the FIRST value the profile does not define is
    /// the one named.
    /// </summary>
    [Fact]
    public void ANullAheadOfATypo_DoesNotSwallowIt()
    {
        var refusal = Assert.Throws<ArgumentException>(
            () => new CaepInteropProfilePolicy(null!, "sesion-revoked"));

        Assert.Contains("<null>", refusal.Message);
    }

    [Fact]
    public async Task AnEventCarryingReasonAdmin_IsDispatched()
    {
        var (dispatcher, outbox, _) = await CreateAsync(CaepEventTypes.SessionRevoked, new CaepInteropProfilePolicy());

        var reached = await dispatcher.DispatchAsync(
            Descriptor(
                CaepEventTypes.SessionRevoked,
                new SessionRevokedPayload
                {
                    ReasonAdmin = new Dictionary<string, string> { ["en"] = "Landspeed policy violation" },
                }),
            Cancellation);

        Assert.Equal(1, reached);
        Assert.Single(await outbox.PendingAsync("s-1", null, Cancellation));
    }

    /// <summary>
    /// The control that keeps every existing deployment working: the profile is a claim a deployment makes,
    /// not a fact about the library, so a host that registered no policy dispatches what it always did.
    /// </summary>
    /// <remarks>
    /// Without this row, making the check unconditional would satisfy every other row here and break each
    /// transmitter that never claimed the profile.
    /// </remarks>
    [Fact]
    public async Task WithNoPolicyRegistered_TheSameEventIsDispatched()
    {
        var (dispatcher, outbox, _) = await CreateAsync(CaepEventTypes.SessionRevoked, payloadPolicy: null);

        var reached = await dispatcher.DispatchAsync(
            Descriptor(CaepEventTypes.SessionRevoked, new SessionRevokedPayload()), Cancellation);

        Assert.Equal(1, reached);
        Assert.Single(await outbox.PendingAsync("s-1", null, Cancellation));
    }

    /// <summary>
    /// An event type the profile says nothing about is dispatched with the policy on. The profile's Section
    /// 3 names three use cases; CAEP 1.0 defines more, and the rule belongs to the three.
    /// </summary>
    [Fact]
    public async Task AnEventTypeOutsideTheProfilesUseCases_IsUntouched()
    {
        var (dispatcher, outbox, _) = await CreateAsync(
            CaepEventTypes.SessionEstablished, new CaepInteropProfilePolicy());

        var reached = await dispatcher.DispatchAsync(
            Descriptor(CaepEventTypes.SessionEstablished, new SessionEstablishedPayload()), Cancellation);

        Assert.Equal(1, reached);
        Assert.Single(await outbox.PendingAsync("s-1", null, Cancellation));
    }

    /// <summary>
    /// The framework's own door is not judged, and that is a decision rather than an oversight.
    /// </summary>
    /// <remarks>
    /// It carries verification and stream-updated events, minted by this library and reached through a
    /// receiver's own request. Its callers write state first - the verification throttle, the stream
    /// status - so a refusal there would fire mid-operation and turn a conformant receiver's verification
    /// request into a fault, breaking the very profile the policy was registered to claim. A policy speaks
    /// about what the HOST asks this transmitter to emit.
    /// </remarks>
    [Fact]
    public async Task TheFrameworksOwnDoor_IsNotJudged()
    {
        var (dispatcher, outbox, stream) = await CreateAsync(
            CaepEventTypes.SessionRevoked, new CaepInteropProfilePolicy());

        await dispatcher.DispatchToStreamAsync(
            stream,
            Descriptor(CaepEventTypes.SessionRevoked, new SessionRevokedPayload()),
            asStatusAnnouncement: false,
            cancellationToken: Cancellation);

        Assert.Single(await outbox.PendingAsync("s-1", null, Cancellation));
    }

    /// <summary>
    /// A relayed event is judged by what its JSON carries, not by which C# class holds it.
    /// </summary>
    /// <remarks>
    /// An event of an unregistered type arrives as raw JSON and can be re-dispatched. Judging it by its
    /// class would refuse a fully conformant event while telling its owner it carries no
    /// <c>reason_admin</c> - a statement about contents nothing had read. The pair is the point: same
    /// class, opposite verdicts, decided by the member.
    /// </remarks>
    /// <remarks>
    /// The empty-object row is its own, and it is what holds the relayed arm's NON-EMPTY half: with only
    /// an absent member and a populated one, weakening <c>is JsonObject { Count: &gt; 0 }</c> to
    /// <c>is JsonObject</c> leaves the whole suite green, because the typed arm's holder cannot see the
    /// relayed one.
    /// </remarks>
    [Theory]
    [InlineData(RelayedMember.Populated)]
    [InlineData(RelayedMember.Absent)]
    [InlineData(RelayedMember.EmptyObject)]
    public async Task ARelayedPayload_IsJudgedByItsJson(RelayedMember member)
    {
        var populated = member is RelayedMember.Populated;
        var json = new JsonObject();
        if (populated)
        {
            json[CaepClaimNames.ReasonAdmin] = new JsonObject { ["en"] = "Landspeed policy violation" };
        }
        else if (member is RelayedMember.EmptyObject)
        {
            json[CaepClaimNames.ReasonAdmin] = new JsonObject();
        }

        var (dispatcher, outbox, _) = await CreateAsync(
            CaepEventTypes.SessionRevoked, new CaepInteropProfilePolicy());
        var descriptor = Descriptor(CaepEventTypes.SessionRevoked, new UnknownEventPayload(json));

        if (populated)
        {
            Assert.Equal(1, await dispatcher.DispatchAsync(descriptor, Cancellation));
            Assert.Single(await outbox.PendingAsync("s-1", null, Cancellation));
        }
        else
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => dispatcher.DispatchAsync(descriptor, Cancellation));
        }
    }

    /// <summary>
    /// A payload this policy cannot read is refused, and told so in those words.
    /// </summary>
    /// <remarks>
    /// The third answer, and it needs its own message. Saying "this event carries none" of a payload
    /// nothing read is a false statement about contents, and it sends a host looking for a member that may
    /// well be there.
    /// </remarks>
    [Fact]
    public async Task APayloadThisPolicyCannotRead_IsRefusedInThoseWords()
    {
        var (dispatcher, _, _) = await CreateAsync(
            CaepEventTypes.SessionRevoked, new CaepInteropProfilePolicy());

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => dispatcher.DispatchAsync(
                Descriptor(CaepEventTypes.SessionRevoked, new HostsOwnPayload()), Cancellation));

        Assert.Contains("cannot be read", refusal.Message);
        Assert.Contains(nameof(HostsOwnPayload), refusal.Message);
    }

    /// <summary>
    /// A deployment claiming one use case may still emit the others as plain CAEP 1.0 events.
    /// </summary>
    /// <remarks>
    /// The profile's Section 1 says so outright: "Support for all use cases listed herein is not required
    /// in order to be considered compliant with this profile. An implementation can choose specific use
    /// cases to support." Enforcing all three on a deployment that claimed one refuses an event both
    /// documents permit, and the only escape would have been to drop enforcement on the claimed one too.
    /// </remarks>
    [Fact]
    public async Task AnUnclaimedUseCase_IsLeftToCaep10()
    {
        var (dispatcher, outbox, _) = await CreateAsync(
            CaepEventTypes.SessionRevoked,
            new CaepInteropProfilePolicy(CaepEventTypes.CredentialChange));

        var reached = await dispatcher.DispatchAsync(
            Descriptor(CaepEventTypes.SessionRevoked, new SessionRevokedPayload()), Cancellation);

        Assert.Equal(1, reached);
        Assert.Single(await outbox.PendingAsync("s-1", null, Cancellation));
    }

    /// <summary>
    /// The policy reaches the dispatcher the container builds, which is the only dispatcher a real
    /// deployment ever holds.
    /// </summary>
    /// <remarks>
    /// Every row above constructs the dispatcher by hand, so all of them would pass over a policy the
    /// container never injects - a registration nobody resolves reads exactly like a working feature. This
    /// row resolves it the way a host does, and its twin asserts the optional dependency stays optional:
    /// a container with nothing registered must still produce a dispatcher.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ThePolicyRegisteredInTheContainer_ReachesTheDispatcher(bool claimsTheProfile)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurityEvents(options => options.SigningKeySource = _ => Task.FromResult<JsonWebKey>(
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));
        services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Issuer,
            EventsSupported = [CaepEventTypes.SessionRevoked],
            PollEndpointFactory = streamId => new Uri($"{Issuer}/ssf/poll/{streamId}"),
        });

        if (claimsTheProfile)
        {
            services.AddSingleton<IEventPayloadPolicy, CaepInteropProfilePolicy>();
        }

        await using var provider = services.BuildServiceProvider();
        var dispatcher = provider.GetRequiredService<EventDispatcher>();
        var descriptor = Descriptor(CaepEventTypes.SessionRevoked, new SessionRevokedPayload());

        if (claimsTheProfile)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => dispatcher.DispatchAsync(descriptor, Cancellation));
        }
        else
        {
            // No stream is subscribed here, so zero is the honest answer - and the point is that it
            // ANSWERED rather than refused.
            Assert.Equal(0, await dispatcher.DispatchAsync(descriptor, Cancellation));
        }
    }

    /// <summary>What a relayed payload's <c>reason_admin</c> looks like on the wire.</summary>
    public enum RelayedMember
    {
        /// <summary>A non-empty object, which is what the profile asks a transmitter for.</summary>
        Populated,

        /// <summary>No member at all.</summary>
        Absent,

        /// <summary>The member present and empty, which CAEP 1.0 Section 2 refuses on its own.</summary>
        EmptyObject,
    }

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private static IEventPayload PayloadFor(string eventType) => eventType switch
    {
        CaepEventTypes.SessionRevoked => new SessionRevokedPayload(),
        CaepEventTypes.CredentialChange => new CredentialChangePayload
        {
            // Required by CAEP 1.0 Section 3.3.1, which is why the compiler holds them. The profile
            // says something weaker about the pair - "Transmitters MAY generate any allowable value of
            // this field" - and something stronger about reason_admin, which is the member nothing held.
            CredentialType = CredentialChangePayload.CredentialTypes.Password,
            ChangeType = CredentialChangePayload.ChangeTypes.Revoke,
        },
        CaepEventTypes.DeviceComplianceChange => new DeviceComplianceChangePayload
        {
            PreviousStatus = DeviceComplianceChangePayload.ComplianceStatuses.Compliant,
            CurrentStatus = DeviceComplianceChangePayload.ComplianceStatuses.NotCompliant,
        },
        _ => throw new ArgumentOutOfRangeException(nameof(eventType), eventType, "No payload for this row."),
    };

    private static SecurityEventDescriptor Descriptor(string eventType, IEventPayload payload) => new()
    {
        EventType = eventType,
        Subject = new EmailSubject("jdoe@example.com"),
        Payload = payload,
    };

    private static async Task<(EventDispatcher Dispatcher, InMemoryEventOutbox Outbox, StreamState Stream)>
        CreateAsync(string eventType, IEventPayloadPolicy? payloadPolicy)
    {
        var subject = new EmailSubject("jdoe@example.com");
        var store = new InMemoryStreamStore();
        var stream = new StreamState
        {
            ReceiverId = "receiver-a",
            Status = StreamStatuses.Enabled,
            SubjectsMode = StreamSubjectsMode.None,
            AddedSubjects = [new StreamSubject(subject, Verified: true)],
            RemovedSubjects = [],
            Configuration = new StreamConfiguration
            {
                StreamId = "s-1",
                Issuer = Issuer,
                Audiences = ["https://receiver.example.com/s-1"],
                EventsDelivered = [eventType],
                Delivery = new PollDeliveryMethod(new Uri("https://tr.example.com/poll/s-1")),
            },
        };

        Assert.True(await store.TryCreateAsync(stream, Cancellation));

        var outbox = new InMemoryEventOutbox();
        return (
            new EventDispatcher(
                NullLogger<EventDispatcher>.Instance,
                store,
                outbox,
                new StubSigner(),
                Issuer,
                payloadPolicy: payloadPolicy),
            outbox,
            stream);
    }

    /// <summary>A payload of the host's own, which this policy has no way to read.</summary>
    private sealed class HostsOwnPayload : IEventPayload;

    private sealed class StubSigner : ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
            => Task.FromResult($"signed.{token.JwtId}");
    }
}
