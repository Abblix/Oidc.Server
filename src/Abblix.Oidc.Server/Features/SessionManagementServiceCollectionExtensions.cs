// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring session management.
/// </summary>
public static class SessionManagementServiceCollectionExtensions
{
    /// <summary>
    /// Adds services related to session management and decorates the authorization request processor within
    /// the specified <see cref="IServiceCollection"/>.
    /// </summary>
    public static IServiceCollection AddSessionManagement(this IServiceCollection services)
    {
        services.TryAddScoped<ISessionManagementService, SessionManagementService>();
        return services.Decorate<IAuthorizationRequestProcessor, AuthorizationRequestProcessorDecorator>();
    }

    /// <summary>
    /// Opts the server into the OpenID Connect Session Management check-session endpoint. This single call
    /// registers the check-session handler and re-enables the <see cref="OidcEndpoints.CheckSession"/> flag,
    /// which is off in the default <see cref="OidcOptions.EnabledEndpoints"/>. Many SPAs do not use the
    /// session-management iframe, so it is opt-in: a server that never calls this method exposes no check-session
    /// endpoint and does not advertise it in discovery.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddCheckSession(this IServiceCollection services)
    {
        services.AddCheckSessionEndpoint();
        services.PostConfigure<OidcOptions>(options => options.EnabledEndpoints |= OidcEndpoints.CheckSession);
        services.Configure<EndpointRegistrationMarker>(m => m.Registered |= OidcEndpoints.CheckSession);
        return services;
    }
}
