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
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Transmitter;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// The transmitter's push sender must accept a resilience pipeline from its host, in the one call that covers
/// every client without naming any: a receiver's endpoint is exactly where a transient failure is expected, and
/// the sender itself makes one honest attempt by design.
/// </summary>
public class PushDeliveryResilienceTests
{
    [Fact]
    public async Task OneHostCall_MakesThePushSenderResilient()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        // The whole of what a host writes, naming nothing this library owns.
        services.ConfigureHttpClientDefaults(builder => builder.AddResilienceOfATypicalHost());

        services.AddSecurityEvents();
        services.AddSsfTransmitter(new SsfTransmitterOptions { Issuer = "https://transmitter.test" });

        var receiver = new FlakyOriginHandler(failuresBeforeSuccess: 2);
        services.AddHttpClient(PushDeliveryTransport.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => receiver);

        using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(PushDeliveryTransport.HttpClientName);
        using var httpClient = new HttpClient(handler, disposeHandler: false);

        var response = await httpClient.GetAsync(
            new Uri("https://receiver.test/events"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, receiver.Requests);
    }
}
