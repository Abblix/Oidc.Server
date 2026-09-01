// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Sockets;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// A receiver names the address its stream is delivered to, so that address is input from outside: this is what
/// stops a receiver from pointing a stream at the transmitter's own network and having security event tokens
/// POSTed there.
/// </summary>
public class ReceiverAddressPolicyTests
{
    private static ReceiverAddressPolicy Policy(params Uri[] allowed) => new(new SharedSignalsTransmitterOptions
    {
        Issuer = "https://tr.example.com",
        AllowedReceiverAddresses = allowed,
    });

    private static ReceiverAddressPolicy PolicyResolving(params IPAddress[] answers) => new(
        new SharedSignalsTransmitterOptions { Issuer = "https://tr.example.com" },
        (_, _) => Task.FromResult(answers));

    [Theory]
    [InlineData("https://169.254.169.254/events")]     // cloud metadata
    [InlineData("https://127.0.0.1/events")]           // loopback
    [InlineData("https://10.1.2.3/events")]            // private
    [InlineData("https://192.168.0.5/events")]         // private
    [InlineData("https://[::1]/events")]               // loopback, IPv6
    [InlineData("https://[::ffff:169.254.169.254]/events")] // metadata behind an IPv4-mapped IPv6 address
    [InlineData("https://localhost/events")]           // internal name
    [InlineData("https://vault.internal/events")]      // internal TLD
    [InlineData("https://receiver/events")]            // single label
    [InlineData("http://receiver.example.com/events")] // cleartext
    public async Task AnAddressInsideTheNetworkIsRefused(string endpoint)
    {
        var rejection = await Policy().RejectionOf(
            new Uri(endpoint), TestContext.Current.CancellationToken);

        Assert.NotNull(rejection);
    }

    /// <summary>
    /// The half that keeps the policy honest: a permission an operator wrote reaches a receiver of its own, at an
    /// address the rules above would refuse.
    /// </summary>
    [Fact]
    public async Task AnAddressTheOperatorPermittedIsReached()
    {
        var policy = Policy(new Uri("https://10.1.2.3"));

        var rejection = await policy.RejectionOf(
            new Uri("https://10.1.2.3/events"), TestContext.Current.CancellationToken);

        Assert.Null(rejection);
    }

    /// <summary>
    /// A permission names one origin, not a posture: permitting one receiver must not permit its neighbour.
    /// </summary>
    [Fact]
    public async Task APermissionDoesNotCoverAnotherAddress()
    {
        var policy = Policy(new Uri("https://10.1.2.3"));

        var rejection = await policy.RejectionOf(
            new Uri("https://10.1.2.4/events"), TestContext.Current.CancellationToken);

        Assert.NotNull(rejection);
    }

    /// <summary>
    /// The only "allow" verdict production traffic actually reaches: an ordinary public receiver, whose name
    /// resolves to a public address, is permitted. Without this case the resolved-address branch could be
    /// inverted and the suite would stay green.
    /// </summary>
    [Fact]
    public async Task AResolvedPublicAddressIsPermitted()
    {
        var policy = PolicyResolving(IPAddress.Parse("93.184.216.34"));

        var rejection = await policy.RejectionOf(
            new Uri("https://receiver.example.com/events"), TestContext.Current.CancellationToken);

        Assert.Null(rejection);
    }

    /// <summary>
    /// Every resolved address must be acceptable, not just the first: a name answering with one public and one
    /// private address is refused, because the connection could take either.
    /// </summary>
    [Fact]
    public async Task ANameResolvingToAnyPrivateAddressIsRefused()
    {
        var policy = PolicyResolving(IPAddress.Parse("93.184.216.34"), IPAddress.Parse("10.0.0.5"));

        var rejection = await policy.RejectionOf(
            new Uri("https://receiver.example.com/events"), TestContext.Current.CancellationToken);

        // Named on the private answer, not the public one: the refusal is about the address that would have let
        // the connection inside, which pins the "every answer" rule rather than "the first answer".
        Assert.NotNull(rejection);
        Assert.Contains("10.0.0.5", rejection);
    }

    /// <summary>
    /// A name that does not resolve is refused rather than delivered to: an unresolvable endpoint is not a public
    /// receiver.
    /// </summary>
    [Fact]
    public async Task ANameThatDoesNotResolveIsRefused()
    {
        var policy = new ReceiverAddressPolicy(
            new SharedSignalsTransmitterOptions { Issuer = "https://tr.example.com" },
            (host, _) => throw new SocketException());

        var rejection = await policy.RejectionOf(
            new Uri("https://receiver.example.com/events"), TestContext.Current.CancellationToken);

        Assert.NotNull(rejection);
    }

    /// <summary>
    /// The sender refuses to spend a queue on a receiver whose address it may not reach, and holds the events
    /// instead: an operator can put the configuration right, and the events are still owed.
    /// </summary>
    [Fact]
    public async Task TheSenderRefusesToDeliverToARefusedAddress()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.Accepted);
        var outbox = new InMemoryEventOutbox();
        await outbox.EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

        var sender = new PushDeliverySender(handler.CreateClient(), outbox, Policy(), NullLogger<PushDeliverySender>.Instance);
        var stream = new StreamState
        {
            ReceiverId = "receiver-a",
            Status = StreamStatuses.Enabled,
            SubjectsMode = StreamSubjectsMode.None,
            Configuration = new StreamConfiguration
            {
                StreamId = "s-1",
                Issuer = "https://tr.example.com",
                Audiences = ["https://receiver.example.com"],
                EventsDelivered = [],
                Delivery = new PushDeliveryMethod(new Uri("https://169.254.169.254/events")),
            },
        };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => sender.SendPendingAsync(stream, TestContext.Current.CancellationToken));

        // Nothing was sent, and the event is still there for a pass made after the address is corrected.
        Assert.Empty(handler.Requests);
        Assert.Single(await outbox.PendingAsync("receiver-a", "s-1", null, TestContext.Current.CancellationToken));
    }
}
