// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.RequestFetching;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the Client-Initiated Backchannel Authentication (CIBA) endpoint and its validation pipeline.
/// </summary>
public static class BackChannelAuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Configures services for handling back-channel authentication requests, enabling secure server-to-server
    /// authentication flows.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddBackChannelAuthenticationEndpoint(this IServiceCollection services)
    {
        services.AddBackChannelAuthenticationContextValidators();

        services.TryAddScoped<IBackChannelAuthenticationRequestFetcher, BackChannelAuthentication.RequestFetching.RequestObjectFetchAdapter>();
        services.TryAddScoped<IBackChannelAuthenticationHandler, BackChannelAuthenticationHandler>();
        services.TryAddScoped<IBackChannelAuthenticationRequestValidator, BackChannelAuthenticationRequestValidator>();
        services.TryAddScoped<IBackChannelAuthenticationRequestProcessor, BackChannelAuthenticationRequestProcessor>();

        return services;
    }

    /// <summary>
    /// Configures and registers a composite of back-channel authentication context validators
    /// into the service collection. Validators run in sequence to verify the client, the
    /// requested resources and scopes, the user identity hint, the requested expiry, the user
    /// code, and the ping-mode configuration before a CIBA request is accepted.
    /// </summary>
    /// <param name="services">The service collection to which the back-channel authentication context validators will be added.</param>
    /// <returns>The modified service collection with the registered back-channel authentication context validators.</returns>
    public static IServiceCollection AddBackChannelAuthenticationContextValidators(this IServiceCollection services)
    {
        // compose BackChannelAuthenticationValidationContext validation as a pipeline of several IBackChannelAuthenticationContextValidator
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ClientValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ResourceValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthentication.Validation.ScopeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, UserIdentityValidator>(),
            // Beside the identity hints, because it answers the same question by the other parameter the
            // specification names for it.
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator,
                BackChannelAuthentication.Validation.RequestedSubjectValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator,
                BackChannelAuthentication.Validation.RequiredAuthContextClassRefValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, RequestedExpiryValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, UserCodeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, PingModeValidator>(),
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, PushModeValidator>(),
            // RFC 9396 section 3 authorization_details on CIBA backchannel auth requests.
            ServiceDescriptor.Singleton<IBackChannelAuthenticationContextValidator, BackChannelAuthorizationDetailsValidator>(),
        ]);
        return services.Compose<IBackChannelAuthenticationContextValidator, BackChannelAuthenticationValidatorComposite>();
    }
}
