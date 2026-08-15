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

using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Abblix.Tests.Shared;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Every outbound client of this library must accept a resilience pipeline from its host - retries and a circuit
/// breaker - without this library knowing about it. What makes that possible is the client coming from
/// <see cref="IHttpClientFactory"/> under an identifier a host can name.
/// </summary>
/// <remarks>
/// Asserted by driving the composed chain rather than by looking for a handler type: a pipeline that is present but
/// not invoked would pass a structural check, and what a host is promised is behaviour. The primary handler is
/// replaced with a stub, which is why the SSRF guarantee is not what this file measures - that belongs to
/// <see cref="OutboundHttpClientSsrfWiringTests"/> and is asserted separately there.
/// </remarks>
public class OutboundHttpClientResilienceTests
{
    [Theory]
    [InlineData(BackChannelNotificationTransport.HttpClientName)] // CIBA ping and push notifications
    [InlineData(BackChannelLogoutTransport.HttpClientName)]                      // back-channel logout
    [InlineData(SecureFetchTransport.HttpClientName)]                      // JWKS, request_uri, software statement
    public async Task EveryOutboundClient_AcceptsAHostResiliencePipeline(string clientName)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddBackChannelAuthentication();
        services.AddBackChannelLogout();

        var origin = new FlakyOriginHandler(failuresBeforeSuccess: 2);
        services.AddHttpClient(clientName)
            .AddResilienceOfATypicalHost()
            .ConfigurePrimaryHttpMessageHandler(() => origin);

        await using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(clientName);
        using var httpClient = new HttpClient(handler, disposeHandler: false);

        var response = await httpClient.GetAsync(
            new Uri("https://origin.test/"), TestContext.Current.CancellationToken);

        // Two failures were absorbed and the third attempt answered, so the pipeline the host added is not merely
        // registered on this client - it runs on this client's requests.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, origin.Requests);
    }

    /// <summary>
    /// The shortest path of all, and the one to document: a host that wants every outbound call resilient names no
    /// client at all.
    /// </summary>
    /// <remarks>
    /// <see cref="HttpClientFactoryServiceCollectionExtensions.ConfigureHttpClientDefaults"/> applies to clients
    /// registered before and after it alike, so it holds however the host orders its registrations - which is what
    /// makes it safe to recommend without a caveat about ordering.
    /// </remarks>
    [Theory]
    [InlineData(BackChannelNotificationTransport.HttpClientName)]
    [InlineData(BackChannelLogoutTransport.HttpClientName)]
    [InlineData(SecureFetchTransport.HttpClientName)]
    public async Task OneHostCall_MakesEveryOutboundClientResilient(string clientName)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();

        // The whole of what a host writes, naming nothing this library owns.
        services.ConfigureHttpClientDefaults(builder => builder.AddResilienceOfATypicalHost());

        services.AddSecureHttpFetch();
        services.AddBackChannelAuthentication();
        services.AddBackChannelLogout();

        // Only to give the test an origin. It cannot be done through the defaults above: this library sets the
        // primary handler of its client-callback clients to the SSRF validator, and a per-client setting wins over
        // a default - which is the guarantee that no host-wide default can switch that validation off.
        var origin = new FlakyOriginHandler(failuresBeforeSuccess: 2);
        services.AddHttpClient(clientName).ConfigurePrimaryHttpMessageHandler(() => origin);

        await using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(clientName);
        using var httpClient = new HttpClient(handler, disposeHandler: false);

        var response = await httpClient.GetAsync(
            new Uri("https://origin.test/"), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(3, origin.Requests);
    }

    /// <summary>
    /// The path a host is told to take: adding the real resilience pipeline leaves the SSRF validation in place,
    /// so retries and a circuit breaker cost nothing in security.
    /// </summary>
    /// <remarks>
    /// Asserted with the shipping <c>AddStandardResilienceHandler</c> rather than a stand-in handler, because the
    /// promise is about that call specifically: it adds to the chain instead of replacing the primary handler the
    /// validation lives in.
    /// </remarks>
    [Theory]
    [InlineData(BackChannelNotificationTransport.HttpClientName)]
    [InlineData(BackChannelLogoutTransport.HttpClientName)]
    [InlineData(SecureFetchTransport.HttpClientName)]
    public void AddingAResiliencePipeline_KeepsTheSsrfValidation(string clientName)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddBackChannelAuthentication();
        services.AddBackChannelLogout();

        services.AddHttpClient(clientName).AddResilienceOfATypicalHost();

        using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(clientName);

        var guarded = false;
        for (HttpMessageHandler? link = handler; link is not null;)
        {
            if (link is SsrfValidatingHttpMessageHandler) guarded = true;
            link = link is DelegatingHandler delegating ? delegating.InnerHandler : null;
        }

        Assert.True(guarded, $"The resilience pipeline must not displace SSRF validation on '{clientName}'.");
    }

    /// <summary>
    /// Each client is configured on its own: a pipeline put on one leaves its neighbours as they were, so a host
    /// can retry a client's notifications hard while leaving a metadata fetch to fail fast.
    /// </summary>
    /// <remarks>
    /// The untouched neighbour is what carries the claim. Asserting only that the configured client retries would
    /// hold just as well if the setting had leaked onto every client in the host, which is the mistake this guards.
    /// </remarks>
    [Fact]
    public async Task ConfiguringOneClient_LeavesItsNeighbourUntouched()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddBackChannelAuthentication();
        services.AddBackChannelLogout();

        var notificationOrigin = new FlakyOriginHandler(failuresBeforeSuccess: 2);
        services.AddHttpClient(BackChannelNotificationTransport.HttpClientName)
            .AddResilienceOfATypicalHost()
            .ConfigurePrimaryHttpMessageHandler(() => notificationOrigin);

        // The neighbour gets an origin and nothing else - no pipeline of its own.
        var logoutOrigin = new FlakyOriginHandler(failuresBeforeSuccess: 2);
        services.AddHttpClient(BackChannelLogoutTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => logoutOrigin);

        await using var provider = services.BuildServiceProvider();
        var handlerFactory = provider.GetRequiredService<IHttpMessageHandlerFactory>();

        using var notificationHandler =
            handlerFactory.CreateHandler(BackChannelNotificationTransport.HttpClientName);
        using var notifications = new HttpClient(notificationHandler, disposeHandler: false);
        var notification = await notifications.GetAsync(
            new Uri("https://origin.test/"), TestContext.Current.CancellationToken);

        using var logoutHandler = handlerFactory.CreateHandler(BackChannelLogoutTransport.HttpClientName);
        using var logouts = new HttpClient(logoutHandler, disposeHandler: false);
        var logout = await logouts.GetAsync(
            new Uri("https://origin.test/"), TestContext.Current.CancellationToken);

        // The configured client rode out both failures; the neighbour took the first one as its answer.
        Assert.Equal(HttpStatusCode.OK, notification.StatusCode);
        Assert.Equal(3, notificationOrigin.Requests);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, logout.StatusCode);
        Assert.Equal(1, logoutOrigin.Requests);
    }
}
