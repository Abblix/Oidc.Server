// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession.Validation;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the session management endpoints: check session and end session.
/// </summary>
public static class SessionServiceCollectionExtensions
{
    /// <summary>
    /// Registers services for handling check session requests, facilitating session management in compliance with
    /// OpenID Connect session management standards.
    /// </summary>
    /// <remarks>
    /// Adds a scoped service for processing check session requests, allowing clients to query the authentication status
    /// of the user in an iframe. This is part of the OpenID Connect session management specification,
    /// enabling applications to maintain a consistent user session state across different clients and
    /// the identity provider. It supports functionalities for clients to detect when a user's session has ended
    /// at the identity provider, prompting for re-authentication or logout as necessary.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with check session endpoint support.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>, enabling further chaining of service registrations.</returns>
    internal static IServiceCollection AddCheckSessionEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<ICheckSessionHandler, CheckSessionHandler>();
        services.AddEndpointSpan<ICheckSessionHandler, TracedCheckSessionHandler>();
        return services;
    }

    /// <summary>
    /// Adds services for handling end session (logout) requests aligning with OpenID Connect session management
    /// specifications. This setup enables the application to handle logout requests effectively, ensuring that
    /// user sessions are terminated securely across all involved parties.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddEndSessionEndpoint(this IServiceCollection services)
    {
        services.AddEndSessionContextValidators();
        services.TryAddScoped<IEndSessionHandler, EndSessionHandler>();
        services.AddEndpointSpan<IEndSessionHandler, TracedEndSessionHandler>();
        services.TryAddScoped<IEndSessionRequestValidator, EndSessionRequestValidator>();
        services.TryAddScoped<IEndSessionRequestProcessor, EndSessionRequestProcessor>();
        return services;
    }

    /// <summary>
    /// Configures and registers a composite of end-session context validators into the service
    /// collection. Validators run in sequence to verify the <c>id_token_hint</c>, the client,
    /// the post-logout redirect URI, and the confirmation claim before an end-session request
    /// is accepted.
    /// </summary>
    /// <param name="services">The service collection to which the end-session context validators will be added.</param>
    /// <returns>The modified service collection with the registered end-session context validators.</returns>
    public static IServiceCollection AddEndSessionContextValidators(this IServiceCollection services)
    {
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IEndSessionContextValidator, EndSession.Validation.IdTokenHintValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, EndSession.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IEndSessionContextValidator, EndSession.Validation.PostLogoutRedirectUrisValidator>(),
            // Scoped, unlike its siblings: it reads the session the user agent holds, which lives for the request.
            // Compose takes the shortest lifetime among the members, so the composite follows it down.
            ServiceDescriptor.Scoped<IEndSessionContextValidator, ConfirmationValidator>()
        ]);
        return services.Compose<IEndSessionContextValidator, EndSessionContextValidatorComposite>();
    }
}
