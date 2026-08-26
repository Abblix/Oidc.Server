// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Sockets;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// A delivery address the transmitter can never use is refused when the receiver proposes it, not
/// every time delivery is attempted afterwards.
/// </summary>
/// <remarks>
/// <para>
/// Consulted only by the sender, the policy would accept a stream naming an address this transmitter
/// refuses on principle - cleartext, or a host inside the transmitter's own network - and then refuse
/// every pass over it, forever. The receiver cannot learn that from a 201, and the refusal reaches
/// only a log it has no access to.
/// </para>
/// <para>
/// Every verb that writes a delivery is covered here, and each refusal is paired with the same request
/// over https. Three verbs write one field, so a check on one of them leaves the hole one call along -
/// which is the door a receiver reaches by accident: create with what works, then move the endpoint.
/// </para>
/// <para>
/// What a registration may judge is what the NAME settles: the scheme, a host spelling out this
/// deployment's own network, an IP literal, an operator's permission. None of those can differ between
/// registration and delivery, so refusing them later says nothing the transmitter did not already know.
/// What the name RESOLVES to is not among them, and is left to delivery.
/// </para>
/// <para>
/// One policy answers both, and the registration question is a strict PREFIX of the delivery one rather
/// than a second copy - so the two cannot come to disagree. A rule restated at a call site is a rule
/// with two versions, and nothing tells you which one an address met.
/// </para>
/// </remarks>
public class StreamAddressAtRegistrationTests
{
    private const string Receiver = "receiver-a";
    private const string EventType = "https://example.com/events/type-a";

    private static readonly Uri Cleartext = new("http://receiver.example.com/ssf/push");
    private static readonly Uri Secure = new("https://receiver.example.com/ssf/push");

    [Fact]
    public async Task ACleartextAddress_IsRefusedWhenItIsProposed()
    {
        var service = Service();

        var created = await service.CreateStreamAsync(
            Receiver, Request(Cleartext), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, created.StatusCode);
    }

    /// <summary>The control: the same request over https is created, so the refusal is about the address.</summary>
    [Fact]
    public async Task ASecureAddress_IsAccepted()
    {
        var service = Service();

        var created = await service.CreateStreamAsync(
            Receiver, Request(Secure), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
    }

    /// <summary>An operator who named the origin gets it at registration too, not only at delivery.</summary>
    /// <remarks>
    /// Otherwise the escape hatch would be half an escape: the deployment that needs it is exactly the
    /// one whose receiver cannot register.
    /// </remarks>
    [Fact]
    public async Task ANamedOrigin_IsAcceptedEvenInCleartext()
    {
        var service = Service(allowed: [new Uri("http://receiver.example.com")]);

        var created = await service.CreateStreamAsync(
            Receiver, Request(Cleartext), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
    }

    /// <summary>An update may not walk a live stream onto an address a create would have refused.</summary>
    /// <remarks>
    /// Checking only the create leaves the same hole one call further along, and that is the shape a
    /// receiver reaches by accident: create with what works, then patch the endpoint.
    /// </remarks>
    [Fact]
    public async Task AnUpdateOntoACleartextAddress_IsRefused()
    {
        var service = Service();
        var ct = TestContext.Current.CancellationToken;

        var created = await service.CreateStreamAsync(Receiver, Request(Secure), ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var updated = await service.UpdateStreamAsync(
            Receiver,
            new UpdateStreamRequest
            {
                StreamId = created.Body!.StreamId,
                Delivery = new PushDeliveryMethod(Cleartext),
            },
            ct);

        Assert.Equal(HttpStatusCode.BadRequest, updated.StatusCode);
    }

    /// <summary>The control for the update: the same call over https goes through.</summary>
    /// <remarks>
    /// Without it the refusal above is satisfied by an update path that refuses every delivery it is
    /// given, which is a check that cannot fail rather than a check.
    /// </remarks>
    [Fact]
    public async Task AnUpdateOntoASecureAddress_IsAccepted()
    {
        var service = Service();
        var ct = TestContext.Current.CancellationToken;

        var created = await service.CreateStreamAsync(Receiver, Request(Secure), ct);

        var updated = await service.UpdateStreamAsync(
            Receiver,
            new UpdateStreamRequest
            {
                StreamId = created.Body!.StreamId,
                Delivery = new PushDeliveryMethod(new Uri("https://elsewhere.example.com/ssf/push")),
            },
            ct);

        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
    }

    /// <summary>A replacement may not walk a live stream onto an address a create would have refused.</summary>
    /// <remarks>
    /// PUT is the verb the specification points a receiver at for exactly this - "use PATCH or PUT to
    /// update or replace the existing stream configuration" (SSF 1.0 Section 8.1.1.1) - so a check that
    /// covers create and update and not replace covers two doors of three.
    /// </remarks>
    [Fact]
    public async Task AReplacementOntoACleartextAddress_IsRefused()
    {
        var service = Service();
        var ct = TestContext.Current.CancellationToken;

        var created = await service.CreateStreamAsync(Receiver, Request(Secure), ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        var replaced = await service.ReplaceStreamAsync(
            Receiver,
            new UpdateStreamRequest
            {
                StreamId = created.Body!.StreamId,
                EventsRequested = [EventType],
                Delivery = new PushDeliveryMethod(Cleartext),
            },
            ct);

        Assert.Equal(HttpStatusCode.BadRequest, replaced.StatusCode);
    }

    /// <summary>The control for the replacement: the same call over https goes through.</summary>
    [Fact]
    public async Task AReplacementOntoASecureAddress_IsAccepted()
    {
        var service = Service();
        var ct = TestContext.Current.CancellationToken;

        var created = await service.CreateStreamAsync(Receiver, Request(Secure), ct);

        var replaced = await service.ReplaceStreamAsync(
            Receiver,
            new UpdateStreamRequest
            {
                StreamId = created.Body!.StreamId,
                EventsRequested = [EventType],
                Delivery = new PushDeliveryMethod(new Uri("https://elsewhere.example.com/ssf/push")),
            },
            ct);

        Assert.Equal(HttpStatusCode.OK, replaced.StatusCode);
    }

    private static CreateStreamRequest Request(Uri endpoint) => new()
    {
        EventsRequested = [EventType],
        Delivery = new PushDeliveryMethod(endpoint),
    };

    /// <summary>A registration does not resolve the name, so a resolver that is down does not refuse one.</summary>
    /// <remarks>
    /// <para>
    /// Resolution is the one part of the address question that is NOT settled when the receiver writes
    /// it: the name is looked up again for every pass. Delivery treats a resolver failure as a condition
    /// an operator recovers from - it holds the queue rather than emptying it - and the same fact
    /// answered at registration would be a terminal 400 instead, with no way for the receiver to tell it
    /// from a permanent refusal. The ordinary case is not exotic: a receiver registers as it starts, and
    /// its own DNS record may still be propagating.
    /// </para>
    /// <para>
    /// The count is asserted as well as the outcome, because a 201 alone would also be true of a
    /// resolver that was consulted and happened to answer.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ARegistration_DoesNotResolveTheName()
    {
        var resolutions = 0;
        var service = Service(resolve: (_, _) =>
        {
            Interlocked.Increment(ref resolutions);
            return Task.FromException<IPAddress[]>(new SocketException((int)SocketError.HostNotFound));
        });

        var created = await service.CreateStreamAsync(
            Receiver, Request(Secure), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(0, resolutions);
    }

    /// <summary>The control: delivery still asks the whole question, resolution included.</summary>
    /// <remarks>
    /// Without it the case above is satisfied by a policy that stopped resolving at all, which would
    /// remove the check that keeps a public name resolving to a private address out of the network.
    /// </remarks>
    [Fact]
    public async Task Delivery_StillJudgesWhatTheNameResolvesTo()
    {
        var policy = new ReceiverAddressPolicy(
            new SharedSignalsTransmitterOptions { Issuer = "https://tr.example.com" },
            (_, _) => Task.FromResult<IPAddress[]>([IPAddress.Parse("169.254.169.254")]));

        Assert.Null(policy.RejectionOfName(Secure));
        Assert.NotNull(await policy.RejectionOf(Secure, TestContext.Current.CancellationToken));
    }

    private static StreamManagementService Service(
        IReadOnlyList<Uri>? allowed = null,
        ReceiverAddressPolicy.HostResolver? resolve = null)
    {
        var options = new SharedSignalsTransmitterOptions
        {
            Issuer = "https://tr.example.com",
            EventsSupported = [EventType],
            PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
            AllowedReceiverAddresses = allowed ?? [],
        };

        var store = new InMemoryStreamStore();
        var outbox = new InMemoryEventOutbox();
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754200000));
        var dispatcher = new EventDispatcher(
            NullLogger<EventDispatcher>.Instance, store, outbox, new NeverSigner(), options.Issuer, clock: clock);

        // A resolver of the test's own, so the one branch of the policy that is not a string comparison
        // stays out of this file: a live DNS lookup would make these tests depend on a name nobody owns.
        var policy = new ReceiverAddressPolicy(
            options,
            resolve ?? ((_, _) => Task.FromResult<IPAddress[]>([IPAddress.Parse("93.184.216.34")])));

        return new StreamManagementService(
            store, outbox, dispatcher, options, policy, PollEndpointsOf(options), clock);
    }

    private sealed class NeverSigner : ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
            => Task.FromResult("signed");
    }
    /// <summary>
    /// The poll address, taken from the options the way the container would. These fixtures name it
    /// through <see cref="SharedSignalsTransmitterOptions.PollEndpointFactory"/>; a host that maps the
    /// endpoints instead has it declared by the mapping, which is covered end to end.
    /// </summary>
    private static PollEndpointLocator PollEndpointsOf(SharedSignalsTransmitterOptions options) => new(options);
}
