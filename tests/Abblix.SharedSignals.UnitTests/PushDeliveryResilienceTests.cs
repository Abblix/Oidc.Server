// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
        await outbox.EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), TestContext.Current.CancellationToken);

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
