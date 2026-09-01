// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
        TimeSpan? interval,
        TimeSpan leaseDuration,
        SharedSignalsTransmitterOptions? hostOptions = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(clock);
        services.AddSecurityEvents();

        // Registered BEFORE the package, so its TryAddSingleton keeps this instance - the shape the
        // method's own parameter documentation advertises, and the only way to hand the argument and
        // the container two different answers about one setting.
        if (hostOptions is not null)
        {
            services.AddSingleton(hostOptions);
        }

        services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
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
            .EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

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
                .PendingAsync("receiver-a", "s-1", null, cancellationToken));

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
            .EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

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
        services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
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
            .EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

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

    /// <summary>
    /// A deployment that drives its own passes gets no sweep from the package, and the setting it is
    /// read from is the one in the CONTAINER.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This sweeper carries no backoff, so running it beside a host's own scheduler puts two pacing
    /// policies on one queue: the host's ceiling is honoured by one of them and ignored by the other,
    /// and nothing but the log says a second sweeper exists.
    /// </para>
    /// <para>
    /// The pre-registered case is the one that needs saying. The registration takes the options as an
    /// argument and hands them to the container with TryAddSingleton, so a host that registered its
    /// own instance first keeps it - which the parameter documentation promises. Deciding from the
    /// argument would therefore judge by a value no other reader sees, and be wrong in both
    /// directions: no sweeper where the host configured one, or a sweeper the host opted out of.
    /// </para>
    /// <para>
    /// Both verdicts come from one setup, so neither reads as the other: nothing swept, then the same
    /// wiring with the interval in place sweeps.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheOptInIsReadFromTheContainer(bool throughTheHostsOwnOptions)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var clock = new FakeTimeProvider(DateTimeOffset.FromUnixTimeSeconds(1754040000));
        var interval = TimeSpan.FromSeconds(30);

        var silent = new AcceptingOrigin();
        await using (var driven = NewTransmitter(silent, clock, null, TimeSpan.FromHours(1)))
        {
            await SweepAndWaitAsync(driven, clock, interval, silent, cancellationToken);

            // The queue is read as well as the origin: "nothing was POSTed" alone would also be true
            // of a pass that ran and found nothing to send.
            Assert.Equal(0, silent.Requests);
            Assert.Single(await driven.GetRequiredService<IEventOutbox>()
                .PendingAsync("receiver-a", "s-1", null, cancellationToken));
        }

        // The control, wired identically save for where the interval is set.
        var sweeping = new AcceptingOrigin();
        var hostOptions = throughTheHostsOwnOptions
            ? new SharedSignalsTransmitterOptions
            {
                Issuer = Issuer,
                PushDeliveryInterval = interval,
                PushDeliveryLeaseDuration = TimeSpan.FromHours(1),
                AllowedReceiverAddresses = [new Uri(ReceiverEndpoint)],
            }
            : null;

        await using var configured = NewTransmitter(
            sweeping,
            clock,
            throughTheHostsOwnOptions ? null : interval,
            TimeSpan.FromHours(1),
            hostOptions);

        await SweepAndWaitAsync(configured, clock, interval, sweeping, cancellationToken);

        Assert.Equal(1, sweeping.Requests);
    }

    /// <summary>Starts the sweeper if there is one, advances until it has delivered, and stops it.</summary>
    /// <remarks>
    /// <para>
    /// An absent scheduler is a way of not sweeping rather than a broken arrangement, so it returns
    /// instead of throwing. The measurement is what the receiver got, which is the same question
    /// whether the sweeper stood down, was never registered, or ran and found nothing - and only that
    /// makes the caller's assertion about DELIVERY rather than about the shape of the container.
    /// </para>
    /// <para>
    /// Advanced repeatedly rather than once: the timer is created inside the service's own task, so a
    /// single advance can land before it exists and be lost. The loop stops on the first delivery, so
    /// a case expecting none pays the full count exactly once.
    /// </para>
    /// </remarks>
    private static async Task SweepAndWaitAsync(
        ServiceProvider provider,
        FakeTimeProvider clock,
        TimeSpan interval,
        AcceptingOrigin origin,
        CancellationToken cancellationToken)
    {
        await provider.GetRequiredService<IStreamStore>().TryCreateAsync(NewPushStream(), cancellationToken);
        await provider.GetRequiredService<IEventOutbox>()
            .EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

        if (provider.GetServices<IHostedService>().OfType<PushDeliveryScheduler>().SingleOrDefault()
            is not { } scheduler)
        {
            return;
        }

        await scheduler.StartAsync(cancellationToken);
        try
        {
            for (var attempt = 0; attempt < 50 && origin.Requests == 0; attempt++)
            {
                clock.Advance(interval);
                await Task.Delay(10, cancellationToken);
            }
        }
        finally
        {
            await scheduler.StopAsync(cancellationToken);
        }
    }
}
