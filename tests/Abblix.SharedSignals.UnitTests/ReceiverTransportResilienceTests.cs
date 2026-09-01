// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Every call a receiver makes outward must accept a resilience pipeline from its host, in the one
/// call that covers every client without naming any.
/// </summary>
/// <remarks>
/// Each case resolves the client from the container and drives it, rather than reading a handler
/// back by the name it was registered under. That is what makes a client the library merely
/// ACCEPTS an <c>HttpClient</c> for fail here: it would never be built by the factory, so nothing
/// a host wrote would reach it, and a test asserting on the registration would not notice.
/// </remarks>
public class ReceiverTransportResilienceTests
{
    private const string TransmitterIssuer = "https://tr.example.com";

    /// <summary>
    /// A receiver wired the ordinary way, with the origin of ONE transport replaced by a flaky
    /// one. The resilience is the single line any host writes; nothing here names a client.
    /// </summary>
    private static ServiceProvider Receiver(string transportName, FlakyOriginHandler origin)
    {
        var services = new ServiceCollection();
        services.AddLogging();

        // The whole of what a host writes, naming nothing this library owns.
        services.ConfigureHttpClientDefaults(builder => builder.AddResilienceOfATypicalHost());

        services.AddSingleton(Mock.Of<IIssuerKeyResolver>());
        services.AddSecurityEvents();
        services.AddSharedSignalsReceiver(new SharedSignalsValidationOptions());
        services.AddSingleton(Mock.Of<ISecurityEventSink>());

        services.AddHttpClient(transportName).ConfigurePrimaryHttpMessageHandler(() => origin);

        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task TheTransmitterConfigurationFetch_IsMadeResilient_ByOneHostCall()
    {
        var origin = new FlakyOriginHandler(
            failuresBeforeSuccess: 2, successContent: $$"""{"issuer": "{{TransmitterIssuer}}"}""");

        await using var provider = Receiver(TransmitterConfigurationTransport.HttpClientName, origin);

        var metadata = await provider.GetRequiredService<TransmitterConfigurationClient>()
            .GetAsync(new Uri(TransmitterIssuer), TestContext.Current.CancellationToken);

        // The document arrived, which the client could only report after two failures were retried away.
        Assert.Equal(TransmitterIssuer, metadata.Issuer);
        Assert.Equal(3, origin.Requests);
    }

    [Fact]
    public async Task ThePoll_IsMadeResilient_ByOneHostCall()
    {
        var origin = new FlakyOriginHandler(failuresBeforeSuccess: 2, successContent: """{"sets": {}}""");

        await using var provider = Receiver(PollDeliveryTransport.HttpClientName, origin);

        var page = await provider.GetRequiredService<PollClient>().PollAsync(
            new Uri($"{TransmitterIssuer}/poll"), new PollRequest(), TestContext.Current.CancellationToken);

        Assert.Empty(page.Sets);
        Assert.Equal(3, origin.Requests);
    }

    [Fact]
    public async Task AStreamManagementCall_IsMadeResilient_ByOneHostCall()
    {
        var origin = new FlakyOriginHandler(failuresBeforeSuccess: 2, successContent: "[]");

        await using var provider = Receiver(StreamManagementTransport.HttpClientName, origin);

        // The one client the container does not build: it is paired with the transmitter's
        // metadata, so the factory supplies the configured transport and the caller the rest.
        var client = provider.GetRequiredService<StreamManagementClientFactory>().Create(
            new TransmitterConfiguration
            {
                Issuer = TransmitterIssuer,
                ConfigurationEndpoint = new Uri($"{TransmitterIssuer}/ssf/streams"),
            });

        var streams = await client.ListAsync(TestContext.Current.CancellationToken);

        Assert.Empty(streams);
        Assert.Equal(3, origin.Requests);
    }
}
