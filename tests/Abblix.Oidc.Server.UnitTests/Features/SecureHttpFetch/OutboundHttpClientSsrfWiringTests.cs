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

using System.Net.Http;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
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
    [InlineData(nameof(HttpNotificationDeliveryService))]
    [InlineData("ILogoutTokenSender")] // default logical name of the typed BackChannelLogoutTokenSender client
    public void ClientCallbackHttpClients_RouteThroughSsrfValidatingHandler(string clientName)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddBackChannelAuthentication();
        services.AddBackChannelLogout();

        using var serviceProvider = services.BuildServiceProvider();
        var handlerFactory = serviceProvider.GetRequiredService<IHttpMessageHandlerFactory>();

        using var handler = handlerFactory.CreateHandler(clientName);

        Assert.True(
            ChainContainsSsrfHandler(handler),
            $"HTTP client '{clientName}' must include {nameof(SsrfValidatingHttpMessageHandler)} in its handler chain.");
    }

    private static bool ChainContainsSsrfHandler(HttpMessageHandler handler)
    {
        for (var current = handler; current is DelegatingHandler delegating; current = delegating.InnerHandler!)
        {
            if (current is SsrfValidatingHttpMessageHandler)
                return true;
        }

        return false;
    }
}
