// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SharedSignals.Transmitter;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// A receiver's delivery address is judged by the guard on the delivery client and nowhere else, so these rows go
/// through the transmitter as a host wires it: the registered client, its real transport, and an origin on the
/// loopback standing for the receiver.
/// </summary>
public class PushDeliveryAddressTests
{
    private static StreamState StreamTo(Uri endpoint) => new()
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
            Delivery = new PushDeliveryMethod(endpoint),
        },
    };

    /// <summary>
    /// A receiver whose name stands for an address inside the network is never connected to, the refusal is logged,
    /// and the event stays queued; the same name permitted by the operator is connected to, which is what makes the
    /// refusal the guard's and not a delivery that never happens.
    /// </summary>
    /// <remarks>
    /// The permitted row connects to the loopback origin, which speaks no TLS and never answers the handshake, so the
    /// delivery is cut off at a short deadline once connected and the event stays queued there too; what it reads is
    /// the connection.
    /// </remarks>
    [Theory]
    [InlineData(false, 0)]
    [InlineData(true, 1)]
    public async Task AReceiverNameStandingForAPrivateAddress_IsConnectedToOnlyWhenPermitted(
        bool permitted,
        int connections)
    {
        using var origin = new LoopbackOrigin();
        var endpoint = new Uri($"https://receiver.example.com:{origin.Port}/events");
        var options = new SharedSignalsTransmitterOptions
        {
            Issuer = "https://transmitter.test",
            AllowedReceiverAddresses = permitted ? [endpoint] : [],
        };

        // The loopback, where the origin listens: refused as private unless permitted, so a guard that stopped
        // refusing would be seen connecting rather than merely failing somewhere else
        var answer = IPAddress.Loopback;
        var log = new RecordingLogger<PushDeliverySender>();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton<ISecurityEventTokenSigner, NamingSigner>();
        services.AddSecurityEvents();
        services.AddSingleton(options);

        // A host replacing the resolution registers the policy itself, as the registration invites
        services.AddSingleton(new ReceiverAddressPolicy(options, (_, _) => Task.FromResult(new[] { answer })));
        services.AddSharedSignalsTransmitter(options);
        services.AddSingleton<ILogger<PushDeliverySender>>(log);
        await using var provider = services.BuildServiceProvider();

        var outbox = provider.GetRequiredService<IEventOutbox>();
        var cancellationToken = TestContext.Current.CancellationToken;
        await outbox.EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        var cutOff = await Record.ExceptionAsync(() =>
            provider.GetRequiredService<PushDeliverySender>().SendPendingAsync(StreamTo(endpoint), deadline.Token));

        // Only the permitted row reaches a handshake that never completes; the refused one ends on its own
        Assert.Equal(permitted, cutOff is OperationCanceledException);

        Assert.Equal(connections, Math.Min(origin.Connections, 1));
        Assert.Single(await outbox.PendingAsync("receiver-a", "s-1", null, cancellationToken));
        Assert.Equal(
            !permitted,
            log.Entries.Any(entry => entry.EventId == LogEvents.Transmitter.ReceiverAddressRefused));
    }

    /// <summary>
    /// The logged refusal names where the receiver is, not its whole endpoint: a secret a receiver carries in the
    /// user information, the path or the query of its endpoint never reaches the operator's log, which is written
    /// on every pass.
    /// </summary>
    [Theory]
    [InlineData("https://169.254.169.254/{0}/events?token={0}")]
    [InlineData("https://{0}@169.254.169.254/events")]
    public async Task TheLoggedRefusal_CarriesNoPartOfTheEndpointBeyondItsOrigin(string endpointFormat)
    {
        const string secret = "s3cr3t-webhook-token";
        var endpoint = new Uri(string.Format(System.Globalization.CultureInfo.InvariantCulture, endpointFormat, secret));
        var options = new SharedSignalsTransmitterOptions { Issuer = "https://transmitter.test" };
        var log = new RecordingLogger<PushDeliverySender>();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton<ISecurityEventTokenSigner, NamingSigner>();
        services.AddSecurityEvents();
        services.AddSharedSignalsTransmitter(options);
        services.AddSingleton<ILogger<PushDeliverySender>>(log);
        await using var provider = services.BuildServiceProvider();

        var outbox = provider.GetRequiredService<IEventOutbox>();
        var cancellationToken = TestContext.Current.CancellationToken;
        await outbox.EnqueueAsync("receiver-a", "s-1", new OutboxItem("jti-1", "a.a.a"), cancellationToken);

        await provider.GetRequiredService<PushDeliverySender>().SendPendingAsync(StreamTo(endpoint), cancellationToken);

        var refusal = Assert.Single(
            log.Entries.Zip(log.Exceptions),
            entry => entry.First.EventId == LogEvents.Transmitter.ReceiverAddressRefused);
        var logged = $"{refusal.First.Message} {refusal.Second}";
        Assert.DoesNotContain(secret, logged, StringComparison.Ordinal);
    }
}
