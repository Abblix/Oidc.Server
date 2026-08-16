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

using Abblix.Tests.Shared;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// The transmitter's push sender must accept a resilience pipeline from its host, in the one call that covers
/// every client without naming any: a receiver's endpoint is exactly where a transient failure is expected, and
/// the sender itself makes one honest attempt by design.
/// </summary>
public class PushDeliveryResilienceTests
{
    /// <summary>
    /// Driven through the real <see cref="PushDeliverySender"/>: a delivery pass succeeds only because the host's
    /// retry absorbed the receiver's two transient failures. Anchoring on the sender rather than on a handler read
    /// back by the same name is what makes a wrong <see cref="PushDeliveryTransport.HttpClientName"/> fail this
    /// test - the sender would then deliver through a client the stub never configured.
    /// </summary>
    [Fact]
    public async Task OneHostCall_MakesThePushSendersDeliveryResilient()
    {
        const string receiverEndpoint = "https://receiver.test/events";

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        // The whole of what a host writes, naming nothing this library owns.
        services.ConfigureHttpClientDefaults(builder => builder.AddResilienceOfATypicalHost());

        services.AddSecurityEvents();
        services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = "https://transmitter.test",

            // The test receiver is a stub, not a host on the network, so it is permitted the way an operator
            // permits a receiver of its own; the resilience being measured is a separate concern.
            AllowedReceiverAddresses = [new Uri(receiverEndpoint)],
        });

        var receiver = new FlakyOriginHandler(failuresBeforeSuccess: 2);
        services.AddHttpClient(PushDeliveryTransport.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => receiver);

        await using var provider = services.BuildServiceProvider();

        var outbox = provider.GetRequiredService<IEventOutbox>();
        await outbox.EnqueueAsync("s-1", new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

        var sender = provider.GetRequiredService<PushDeliverySender>();
        var stream = new StreamState
        {
            ReceiverId = "receiver-a",
            Status = StreamStatuses.Enabled,
            SubjectsMode = StreamSubjectsMode.None,
            Configuration = new StreamConfiguration
            {
                StreamId = "s-1",
                Issuer = "https://transmitter.test",
                Audiences = ["https://receiver.test"],
                EventsDelivered = [],
                Delivery = new PushDeliveryMethod(new Uri(receiverEndpoint)),
            },
        };

        var outcome = await sender.SendPendingAsync(stream, TestContext.Current.CancellationToken);

        // The one event was delivered, which the sender could only report after two failures were retried away.
        Assert.Equal(new PushDeliveryPassOutcome(Delivered: 1, Rejected: 0), outcome);
        Assert.Equal(3, receiver.Requests);
    }
}
