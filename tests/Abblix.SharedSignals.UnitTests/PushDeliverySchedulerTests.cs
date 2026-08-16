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

    /// <summary>Never answers, so a pass reaching it runs until something stops it.</summary>
    private sealed class HangingOrigin : HttpMessageHandler
    {
        private int _requests;

        public int Requests => Volatile.Read(ref _requests);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.Accepted);
        }
    }

    /// <summary>
    /// One stream, one queued event, and a transmitter wired the way the tests below need it.
    /// </summary>
    private static ServiceProvider NewTransmitter(
        HttpMessageHandler origin,
        TimeProvider clock,
        TimeSpan interval,
        TimeSpan leaseDuration)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(clock);
        services.AddSecurityEvents();
        services.AddSsfTransmitter(new SsfTransmitterOptions
        {
            Issuer = Issuer,
            PushDeliveryInterval = interval,
            PushDeliveryLeaseDuration = leaseDuration,

            // The receiver is a stub rather than a host on the network, so it is permitted the way
            // an operator permits a receiver of its own.
            AllowedReceiverAddresses = [new Uri(ReceiverEndpoint)],
        });
        services.AddHttpClient(PushDeliveryTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => origin);

        return services.BuildServiceProvider();
    }

    private static StreamState NewPushStream() => new()
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

    /// <summary>
    /// Every instance of the application runs the scheduler, so what keeps two of them from POSTing
    /// one stream's queue twice over is the claim - and the case is modelled by holding that claim
    /// the way another instance would.
    /// </summary>
    /// <remarks>
    /// The "nothing was delivered" half is a negative, so the same test releases the claim and
    /// requires the delivery to happen: one setup, both verdicts, and neither reading as the other.
    /// </remarks>
    [Fact]
    public async Task AStreamClaimedByAnotherInstance_IsPassedBy_AndDeliveredOnceTheClaimIsReleased()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754040000));
        var origin = new AcceptingOrigin();
        var interval = TimeSpan.FromSeconds(30);

        // Far longer than the whole test advances the clock, so nothing here turns on a deadline
        // firing: this test is about the claim being held, not about it running out.
        await using var provider = NewTransmitter(origin, clock, interval, TimeSpan.FromHours(1));

        await provider.GetRequiredService<IStreamStore>().TryCreateAsync(NewPushStream(), cancellationToken);
        await provider.GetRequiredService<IEventOutbox>()
            .EnqueueAsync("s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

        // The same singleton the scheduler resolves, which is what makes this the other instance
        // rather than a second lock nobody consults.
        var lease = provider.GetRequiredService<IDeliveryLease>();
        var claim = await lease.TryAcquireAsync("push:s-1", TimeSpan.FromHours(1), cancellationToken);
        Assert.NotNull(claim);

        var scheduler = provider.GetServices<IHostedService>().OfType<PushDeliveryScheduler>().Single();
        await scheduler.StartAsync(cancellationToken);

        try
        {
            for (var attempt = 0; attempt < 10; attempt++)
            {
                clock.Advance(interval);
                await Task.Delay(10, cancellationToken);
            }

            Assert.Equal(0, origin.Requests);
            Assert.Single(await provider.GetRequiredService<IEventOutbox>()
                .PendingAsync("s-1", null, cancellationToken));

            await claim.DisposeAsync();

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

    /// <summary>
    /// A claim expires whether or not the pass holding it has finished, so the pass is cut at the
    /// same deadline - otherwise the instance taking the stream over next would be delivering it
    /// alongside one still POSTing, which is what the claim exists to prevent.
    /// </summary>
    /// <remarks>
    /// The verdict is a SECOND request rather than the absence of anything: a pass that was never
    /// cut off is still inside the first one, so the sweep never comes round again and the counter
    /// cannot reach two by any other route.
    /// </remarks>
    [Fact]
    public async Task APassOutlivingItsClaim_IsCutOff_SoTheSweepComesRoundAgain()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754040000));
        var origin = new HangingOrigin();
        var interval = TimeSpan.FromSeconds(10);

        await using var provider = NewTransmitter(origin, clock, interval, TimeSpan.FromSeconds(30));

        await provider.GetRequiredService<IStreamStore>().TryCreateAsync(NewPushStream(), cancellationToken);
        await provider.GetRequiredService<IEventOutbox>()
            .EnqueueAsync("s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

        var scheduler = provider.GetServices<IHostedService>().OfType<PushDeliveryScheduler>().Single();
        await scheduler.StartAsync(cancellationToken);

        try
        {
            for (var attempt = 0; attempt < 100 && origin.Requests < 2; attempt++)
            {
                clock.Advance(interval);
                await Task.Delay(10, cancellationToken);
            }

            Assert.Equal(2, origin.Requests);
        }
        finally
        {
            await scheduler.StopAsync(cancellationToken);
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
