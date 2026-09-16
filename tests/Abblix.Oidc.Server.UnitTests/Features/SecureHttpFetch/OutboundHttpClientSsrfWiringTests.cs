// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// Regression guard: every HTTP client this library uses to POST to a client-supplied URL
/// (the CIBA ping/push notification endpoint and the back-channel logout URI) must route through
/// <see cref="SsrfValidatingHttpMessageHandler"/>. Without it, a client could register an internal
/// URL (e.g. a cloud metadata service) and turn a server-initiated callback into an SSRF vector.
/// </summary>
public class OutboundHttpClientSsrfWiringTests
{
    [Theory]
    [InlineData(BackChannelNotificationTransport.HttpClientName)]
    [InlineData(BackChannelLogoutTransport.HttpClientName)] // default logical name of the typed BackChannelLogoutTokenSender client
    public void ClientCallbackHttpClients_RouteThroughSsrfValidatingHandler(string clientName)
    {
        using var serviceProvider = BuildHost().BuildServiceProvider();
        var handlerFactory = serviceProvider.GetRequiredService<IHttpMessageHandlerFactory>();

        using var handler = handlerFactory.CreateHandler(clientName);

        Assert.True(
            ChainContainsSsrfHandler(handler),
            $"HTTP client '{clientName}' must include {nameof(SsrfValidatingHttpMessageHandler)} in its handler chain.");
    }

    /// <summary>
    /// The published client name is what a host configures resilience through, so it must reach the very client the
    /// library resolves - and the SSRF validation must survive whatever the host chains onto it.
    /// </summary>
    /// <remarks>
    /// Both halves are asserted on one chain because they are one guarantee. The host's handler being present proves
    /// the name is the right one - a wrong name would configure a client nobody uses and read as success - and the
    /// validation sitting DEEPER proves every attempt of a retry pipeline is validated afresh, which is what a
    /// client-supplied address needs when it can start resolving to an internal one between attempts.
    /// </remarks>
    [Fact]
    public void HostConfiguration_ByPublishedName_ReachesTheClient_AndStaysOutsideSsrfValidation()
    {
        var services = BuildHost();

        // What a host writes to add a resilience pipeline, with a handler standing in for one.
        services.AddHttpClient(BackChannelNotificationTransport.HttpClientName)
            .AddHttpMessageHandler(() => new HostHandler());

        using var serviceProvider = services.BuildServiceProvider();
        using var handler = serviceProvider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(BackChannelNotificationTransport.HttpClientName);

        var chain = Chain(handler).ToList();

        var hostPosition = chain.FindIndex(link => link is HostHandler);
        Assert.True(hostPosition >= 0, "The host's handler must be in the chain of the client the library resolves.");

        var ssrfPosition = chain.FindIndex(link => link is SsrfValidatingHttpMessageHandler);
        Assert.True(
            ssrfPosition > hostPosition,
            "SSRF validation must sit deeper than the host's handler, so a retried attempt is validated again.");
    }

    private static ServiceCollection BuildHost()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddBackChannelAuthentication();
        services.AddBackChannelLogout();
        return services;
    }

    private static bool ChainContainsSsrfHandler(HttpMessageHandler handler)
        => Chain(handler).Any(link => link is SsrfValidatingHttpMessageHandler);

    /// <summary>
    /// Walks the handler chain from the outermost handler inwards, ending with the primary one.
    /// </summary>
    private static IEnumerable<HttpMessageHandler> Chain(HttpMessageHandler handler)
    {
        for (var current = handler; current is not null;)
        {
            yield return current;
            current = current is DelegatingHandler delegating ? delegating.InnerHandler : null;
        }
    }

    /// <summary>
    /// A deployed client reaches its transport through the guard, and that transport follows no redirect.
    /// </summary>
    /// <remarks>
    /// A followed 3xx re-sends the request to an address nothing vetted, which is the one bypass the guard cannot
    /// see. The transport the guard builds refuses redirects, and what this row adds is that the assembled client
    /// still arrives at that transport rather than at one a pipeline put in its place. What the transport promises
    /// in the first place belongs to the type that builds it, and is held there.
    /// </remarks>
    [Theory]
    [InlineData(BackChannelNotificationTransport.HttpClientName)]
    [InlineData(BackChannelLogoutTransport.HttpClientName)]
    public void ADeployedClient_ReachesItsTransportThroughTheGuard(string clientName)
    {
        using var serviceProvider = BuildHost().BuildServiceProvider();
        using var handler = serviceProvider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(clientName);

        var guard = Assert.IsType<SsrfValidatingHttpMessageHandler>(
            Chain(handler).Single(link => link is SsrfValidatingHttpMessageHandler));

        var transport = Assert.IsType<HttpClientHandler>(guard.InnerHandler);

        Assert.False(transport.AllowAutoRedirect);
    }

    /// <summary>
    /// The library builds the SSRF handler itself rather than letting the container choose its constructor
    /// arguments.
    /// </summary>
    /// <remarks>
    /// The handler takes an optional name resolution so a test can say what a name stands for. Registered by type,
    /// the container would fill that parameter from any registration of that delegate - and a host has every
    /// reason to register one for something else, at which point it silently decides what every outbound address
    /// of this server resolves to, while the guard is still present and still primary, so the watch over these
    /// clients sees nothing. What this row holds is the library's own registration carrying a factory, and nothing
    /// beyond it: not what the factory passes, and not a host that registers this handler by type itself and wins
    /// the TryAdd, which is a host saying it builds the handler and getting what it asked for.
    /// </remarks>
    [Fact]
    public void TheSsrfHandler_IsBuiltByTheLibrary_NotByTheContainersChoiceOfConstructor()
    {
        var registration = Assert.Single(
            BuildHost(),
            descriptor => descriptor.ServiceType == typeof(SsrfValidatingHttpMessageHandler));

        Assert.NotNull(registration.ImplementationFactory);
    }

    /// <summary>Stands in for whatever a host chains onto the client - a resilience pipeline, a proxy.</summary>
    private sealed class HostHandler : DelegatingHandler;
}
