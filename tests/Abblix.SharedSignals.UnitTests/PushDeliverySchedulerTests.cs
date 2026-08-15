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
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Push delivery happens on its own, which is the whole point: every part of it worked before this
/// and none of them was called, so a host saw events queued and nothing delivered, with nothing
/// logged and no error anywhere.
/// </summary>
public class PushDeliverySchedulerTests
{
    private const string ReceiverEndpoint = "https://receiver.test/events";
    private const string Issuer = "https://transmitter.test";

    /// <summary>Answers every delivery with the 202 RFC 8935 Section 2.2 defines, and counts them.</summary>
    private sealed class AcceptingOrigin : HttpMessageHandler
    {
        private int _requests;

        public int Requests => Volatile.Read(ref _requests);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Accepted));
        }
    }

    [Fact]
    public async Task AQueuedEvent_IsDelivered_WithoutAnybodyAskingForAPass()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754040000));
        var origin = new AcceptingOrigin();
        var interval = TimeSpan.FromSeconds(30);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(clock);
        services.AddSecurityEvents();
        services.AddSsfTransmitter(new SsfTransmitterOptions
        {
            Issuer = Issuer,
            PushDeliveryInterval = interval,

            // The receiver is a stub rather than a host on the network, so it is permitted the way
            // an operator permits a receiver of its own.
            AllowedReceiverAddresses = [new Uri(ReceiverEndpoint)],
        });
        services.AddHttpClient(PushDeliveryTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => origin);

        await using var provider = services.BuildServiceProvider();

        var stream = new StreamState
        {
            ReceiverId = "receiver-a",
            Status = StreamStatuses.Enabled,
            SubjectsMode = StreamSubjectsMode.None,
            Configuration = new StreamConfiguration
            {
                StreamId = "s-1",
                Issuer = Issuer,
                Audiences = ["https://receiver.test"],
                EventsDelivered = [],
                Delivery = new PushDeliveryMethod(new Uri(ReceiverEndpoint)),
            },
        };

        await provider.GetRequiredService<IStreamStore>().TryCreateAsync(stream, cancellationToken);
        await provider.GetRequiredService<IEventOutbox>()
            .EnqueueAsync("s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

        // Nobody calls the sender: the hosted service the registration wired is the only thing that
        // can, and the clock is what makes it.
        var scheduler = provider.GetServices<IHostedService>().OfType<PushDeliveryScheduler>().Single();
        await scheduler.StartAsync(cancellationToken);

        try
        {
            // Advanced until the pass has run, rather than once: the timer is created inside the
            // service's own task, so a single advance can land before it exists and be lost.
            for (var attempt = 0; attempt < 50 && origin.Requests == 0; attempt++)
            {
                clock.Advance(interval);
                await Task.Delay(10, cancellationToken);
            }

            Assert.Equal(1, origin.Requests);
        }
        finally
        {
            await scheduler.StopAsync(cancellationToken);
        }
    }
}
