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
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// A receiver names the address its stream is delivered to, so that address is input from outside: this is what
/// stops a receiver from pointing a stream at the transmitter's own network and having security event tokens
/// POSTed there.
/// </summary>
public class ReceiverAddressPolicyTests
{
    private static ReceiverAddressPolicy Policy(params Uri[] allowed) => new(new SsfTransmitterOptions
    {
        Issuer = "https://tr.example.com",
        AllowedReceiverAddresses = allowed,
    });

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
    /// The sender refuses to spend a queue on a receiver whose address it may not reach, and holds the events
    /// instead: an operator can put the configuration right, and the events are still owed.
    /// </summary>
    [Fact]
    public async Task TheSenderRefusesToDeliverToARefusedAddress()
    {
        var handler = new StubHttpHandler().Enqueue(HttpStatusCode.Accepted);
        var outbox = new InMemoryEventOutbox();
        await outbox.EnqueueAsync("s-1", new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

        var sender = new PushDeliverySender(handler.CreateClient(), outbox, Policy());
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
        Assert.Single(await outbox.PendingAsync("s-1", null, TestContext.Current.CancellationToken));
    }
}
