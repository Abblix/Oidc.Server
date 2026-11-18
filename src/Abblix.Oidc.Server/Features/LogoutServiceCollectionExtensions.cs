// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring logout notification and its channels.
/// </summary>
public static class LogoutServiceCollectionExtensions
{
    /// <summary>
    /// Configures the logout notification machinery and composes whatever logout channels the host has chosen
    /// into a single notifier. The channels themselves are opt-in: a host serves front-channel logout by calling
    /// <see cref="AddFrontChannelLogout"/> and back-channel logout by calling <see cref="AddBackChannelLogout"/>,
    /// at any point before the provider is built.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the logout notification services to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
    /// <remarks>
    /// A deployment that chooses neither channel notifies nobody on logout and advertises neither channel in its
    /// discovery document, which is what such a deployment does. Registering both channels here instead would
    /// decide that for every host: the composite reports a channel as supported when any member supports it, and
    /// the configuration endpoint publishes that as <c>frontchannel_logout_supported</c> and
    /// <c>backchannel_logout_supported</c>, so every provider would announce channels its operator never asked
    /// for, and back-channel logout carries an outbound HTTP client with it.
    /// </remarks>
    public static IServiceCollection AddLogoutNotification(this IServiceCollection services)
    {
        services.TryAddScoped<ISessionLogoutNotifier, SessionLogoutNotifier>();
        services.TryAddScoped<IAuthSessionTerminator, AuthSessionTerminator>();
        services.TryAddSingleton<ILogoutConfirmationStore, LogoutConfirmationStore>();

        // The end-session response formatter renders whatever front-channel URIs the response carries, so it is
        // a constructor dependency of that formatter whether or not this host serves the channel. Leaving it to
        // AddFrontChannelLogout would make a host that serves no front channel unable to answer ANY logout
        // request. It advertises nothing and reaches nobody: with no front-channel notifier there are no URIs
        // to render, and it renders none.
        services.TryAddSingleton<IFrontChannelLogoutService, FrontChannelLogoutService>();

        // The family has to hold a member even when the host serves no channel: an empty family composes to
        // nothing, so everything that resolves the notifier singly would fail to resolve rather than read
        // "neither". A member that supports no channel answers that question and changes no answer for a host
        // that did choose a channel, which is cheaper than teaching each such consumer to resolve the family
        // as a collection and decide what its absence means.
        // Scoped is not an idle choice for a class holding nothing: a composite adopts the shortest lifetime
        // among its members and refuses a member shorter-lived than itself, so a singleton here would compose
        // a singleton for a host serving no channel, and its later opt-in into a scoped channel would throw.
        services.Decompose<ILogoutNotifier>()
            .AddLast(ServiceDescriptor.Scoped<ILogoutNotifier, NoLogoutNotifier>());

        return services.Compose<ILogoutNotifier, CompositeLogoutNotifier>();
    }

    /// <summary>
    /// Adds the necessary services for back-channel logout functionality to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    public static IServiceCollection AddBackChannelLogout(this IServiceCollection services)
    {
        // This method is public and AddLogoutNotification composes the family, so a host calling it directly
        // may well arrive after the composition. Through TryAddEnumerable the notifier would land beside the
        // composite and win the singular resolve, leaving the other channel unnotified while the discovery
        // document still advertised it.
        services.Decompose<ILogoutNotifier>()
            .AddLast(ServiceDescriptor.Scoped<ILogoutNotifier, BackChannelLogoutNotifier>());
        services.TryAddSingleton<ILogoutTokenService, LogoutTokenService>();
        // The back-channel logout URI is a client-supplied URL, so POSTing logout tokens to it must
        // run through the SSRF-validating handler and carry a bounded timeout, like every other
        // server-initiated outbound request in this library.
        return services
            .AddSsrfHttpClient<ILogoutTokenSender, BackChannelLogoutTokenSender>((serviceProvider, client) =>
            {
                client.Timeout = serviceProvider.GetRequiredService<IOptions<SecureHttpFetchOptions>>()
                    .Value.RequestTimeout;
            })
            .Services;
    }

    /// <summary>
    /// Adds the necessary services for front-channel logout functionality to the specified <see cref="IServiceCollection"/>.
    /// Front-channel logout is typically used for web-based applications where the logout request is sent directly from
    /// the user's browser to the identity provider and other logged-in services.
    /// </summary>
    public static IServiceCollection AddFrontChannelLogout(this IServiceCollection services)
    {
        services.Decompose<ILogoutNotifier>()
            .AddLast(ServiceDescriptor.Scoped<ILogoutNotifier, FrontChannelLogoutNotifier>());
        return services;
    }
}
