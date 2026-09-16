// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// A receiver chooses the address its stream is delivered to, so the address check has to live on the connection,
/// not only in front of it: a redirect or a DNS rebinding would otherwise carry a delivery to an address nothing
/// vetted. These tests pin that the transmitter registration installs
/// <see cref="ReceiverAddressValidatingHandler"/> as the push client's primary handler, with redirects disabled.
/// </summary>
public class PushDeliverySsrfWiringTests
{
    private static IHttpMessageHandlerFactory HandlerFactory()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecurityEvents();
        services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions { Issuer = "https://transmitter.test" });
        return services.BuildServiceProvider().GetRequiredService<IHttpMessageHandlerFactory>();
    }

    /// <summary>
    /// The transmitter builds its address policy itself rather than letting the container choose its constructor
    /// arguments.
    /// </summary>
    /// <remarks>
    /// The policy takes an optional name resolution so a test can say what a name stands for. Registered by type,
    /// the container would fill that parameter from any registration of that delegate, and a host that registered
    /// one for something else would silently decide what every delivery address resolves to, with the guard still
    /// in place. A host that registers the policy itself is a different matter: it is saying it builds the policy,
    /// and gets what it asked for.
    /// </remarks>
    [Fact]
    public void TheAddressPolicy_IsBuiltByTheLibrary_NotByTheContainersChoiceOfConstructor()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecurityEvents();
        services.AddSharedSignalsTransmitter(
            new SharedSignalsTransmitterOptions { Issuer = "https://transmitter.test" });

        var registration = Assert.Single(
            services,
            descriptor => descriptor.ServiceType == typeof(ReceiverAddressPolicy));

        Assert.NotNull(registration.ImplementationFactory);
    }

    private static IEnumerable<HttpMessageHandler> Chain(HttpMessageHandler handler)
    {
        for (var current = handler; current is not null;)
        {
            yield return current;
            current = current is DelegatingHandler delegating ? delegating.InnerHandler : null;
        }
    }

    [Fact]
    public void ThePushClientRoutesThroughTheValidatingHandler_WithRedirectsDisabled()
    {
        using var handler = HandlerFactory().CreateHandler(PushDeliveryTransport.HttpClientName);
        var chain = Chain(handler).ToList();

        var guard = Assert.IsType<ReceiverAddressValidatingHandler>(
            chain.Find(link => link is ReceiverAddressValidatingHandler));

        // The redirect-following that would carry a delivery to an unvetted second address is off, so a receiver's
        // 3xx comes back as an ordinary non-success response instead.
        var transport = Assert.IsType<HttpClientHandler>(guard.InnerHandler);
        Assert.False(transport.AllowAutoRedirect);
    }

    /// <summary>
    /// The guard runs on the request itself, before the socket: an internal address is refused on the connection,
    /// which is what a redirect target or a rebound name would present.
    /// </summary>
    [Fact]
    public async Task TheValidatingHandler_RefusesAnInternalAddressBeforeConnecting()
    {
        var probe = new ConnectionProbe();
        var guard = new ReceiverAddressValidatingHandler(
            new ReceiverAddressPolicy(new SharedSignalsTransmitterOptions { Issuer = "https://transmitter.test" }))
        {
            InnerHandler = probe,
        };
        using var client = new HttpClient(guard);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(
            new Uri("https://169.254.169.254/events"), TestContext.Current.CancellationToken));

        // The refusal happened before anything reached the transport.
        Assert.Equal(0, probe.Requests);
    }

    private sealed class ConnectionProbe : HttpMessageHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
