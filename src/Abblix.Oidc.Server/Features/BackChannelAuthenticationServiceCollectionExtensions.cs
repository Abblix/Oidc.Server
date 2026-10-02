// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.GrantProcessors;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring
/// Client-Initiated Backchannel Authentication.
/// </summary>
public static class BackChannelAuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Opts the server into Client-Initiated Backchannel Authentication (CIBA). This single call registers the
    /// CIBA feature services, the CIBA grant handler, the backchannel endpoint services and re-enables the
    /// <see cref="OidcEndpoints.BackChannelAuthentication"/> flag, which is off in the default
    /// <see cref="OidcOptions.EnabledEndpoints"/>. A server that never calls this method exposes no backchannel
    /// endpoint and runs no CIBA grant.
    /// </summary>
    /// <remarks>
    /// Call this <b>before</b> <c>AddOidcCore</c>/<c>AddOidcServices</c>: the CIBA grant handler must be
    /// registered before <c>AddAuthorizationGrants()</c> composes the grant handlers at the end of
    /// <c>AddOidcCore</c>, otherwise it is registered beside the composite and the token endpoint resolves the
    /// wrong single <c>IAuthorizationGrantHandler</c>.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddBackChannelAuthentication(this IServiceCollection services)
    {
        services.TryAddSingleton<IUserDeviceAuthenticationHandler, UserDeviceAuthenticationHandlerStub>();
        services.TryAddSingleton<IAuthenticationRequestIdGenerator, AuthenticationRequestIdGenerator>();
        services.TryAddSingleton<IBackChannelRequestStorage, BackChannelRequestStorage>();
        services.TryAddSingleton<INotificationDeliveryService, HttpNotificationDeliveryService>();

        // Register mode-specific completion handlers as keyed services
        services.TryAddKeyedScoped<AuthenticationCompletionHandler, PollModeCompletionHandler>(
            BackchannelTokenDeliveryModes.Poll);
        services.TryAddKeyedScoped<AuthenticationCompletionHandler, PingModeCompletionHandler>(
            BackchannelTokenDeliveryModes.Ping);
        services.TryAddKeyedScoped<AuthenticationCompletionHandler, PushModeCompletionHandler>(
            BackchannelTokenDeliveryModes.Push);

        // Register router that automatically selects the appropriate mode-specific handler
        services.TryAddScoped<IAuthenticationCompletionHandler, AuthenticationCompletionRouter>();

        // Register mode-specific grant processors as keyed services
        services.TryAddKeyedSingleton<IBackChannelGrantProcessor, PollModeGrantProcessor>(
            BackchannelTokenDeliveryModes.Poll);
        services.TryAddKeyedSingleton<IBackChannelGrantProcessor, PingModeGrantProcessor>(
            BackchannelTokenDeliveryModes.Ping);
        services.TryAddKeyedSingleton<IBackChannelGrantProcessor, PushModeGrantProcessor>(
            BackchannelTokenDeliveryModes.Push);

        // Register long-polling status notifier if long-polling is enabled
        // This service is optional - if not registered, long-polling will be disabled
        services.TryAddSingleton<IBackChannelLongPollingService>(sp =>
        {
            // Registered whatever the long-polling setting says. A factory that answers null publishes a
            // false non-null through the container: a consumer resolving it normally receives the null it
            // was promised was absent, an enumeration yields a null element, and GetRequiredService reports
            // the service as unregistered while a descriptor for it plainly exists. Constructing it when it
            // will not be used costs one object; the alternative costs a diagnosis.
            var logger = sp.GetRequiredService<ILogger<InMemoryLongPollingService>>();
            return new InMemoryLongPollingService(logger);
        });

        // Register HTTP client for backchannel notifications (ping and push modes) with configurable handler lifetime
        // Use configuration callback to get handler lifetime from OidcOptions
        services.AddOptions<HttpClientFactoryOptions>(BackChannelNotificationTransport.HttpClientName)
            .Configure<IOptions<OidcOptions>>((httpOptions, oidcOptions) =>
            {
                httpOptions.HandlerLifetime =
                    oidcOptions.Value.BackChannelAuthentication.NotificationHttpClientHandlerLifetime;
            });

        // The notification endpoint is a client-supplied URL, so server-initiated POSTs to it must
        // run through the SSRF-validating handler (blocks internal hosts, private IPs, DNS rebinding)
        // and carry a bounded timeout, exactly like every other outbound fetch in this library.
        services.AddSsrfHttpClient(BackChannelNotificationTransport.HttpClientName, (serviceProvider, client) =>
        {
            client.Timeout = serviceProvider.GetRequiredService<IOptions<OidcOptions>>()
                .Value.BackChannelAuthentication.NotificationHttpClientTimeout;
        });

        // Register CIBA grant handler (dual: IAuthorizationGrantHandler + IGrantTypeInformer).
        services.AddAuthorizationGrant<BackChannelAuthenticationGrantHandler>();

        // Single opt-in: registering the feature also brings in the backchannel endpoint services and turns the
        // endpoint on. EnabledEndpoints defaults to OidcEndpoints.Base (CIBA off), so a server that never calls this
        // method neither registers the CIBA types nor advertises/validates the endpoint.
        services.AddBackChannelAuthenticationEndpoint();
        services.PostConfigure<OidcOptions>(
            options => options.EnabledEndpoints |= OidcEndpoints.BackChannelAuthentication);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.BackChannelAuthentication);

        return services;
    }
}
