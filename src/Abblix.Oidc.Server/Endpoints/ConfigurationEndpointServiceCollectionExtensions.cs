// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Abblix.Oidc.Server.Features.Telemetry;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the OpenID Connect Discovery (configuration) endpoint.
/// </summary>
public static class ConfigurationEndpointServiceCollectionExtensions
{
    /// <summary>
    /// Adds the configuration handler for OpenID Connect Discovery endpoint.
    /// </summary>
    /// <remarks>
    /// This handler builds discovery metadata according to OpenID Connect Discovery specification,
    /// providing framework-agnostic metadata about the provider's configuration.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddConfigurationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IAuthorizationMetadataProvider, AuthorizationMetadataProvider>();
        services.TryAddScoped<IScopesAndClaimsProvider, ScopesAndClaimsProvider>();
        // Singleton, unlike its scoped neighbours: JwtAlgorithmsProvider is a stateless projection over the
        // singleton IJsonWebTokenCreator/IJsonWebTokenValidator, so scoping it would only make it a captive
        // dependency of the singleton client-registration validators (SigningAlgorithmsValidator and
        // SignedResponseAlgorithmsValidator) that consume it.
        services.TryAddSingleton<IJwtAlgorithmsProvider, JwtAlgorithmsProvider>();
        services.TryAddScoped<IAcrMetadataProvider, AcrMetadataProvider>();
        services.TryAddScoped<IConfigurationHandler, ConfigurationHandler>();
        services.Decorate<IConfigurationHandler, TracedConfigurationHandler>();
        // Scoped to match the adapters' response formatters, which are the only consumers and are themselves
        // scoped: the signature is produced per request over that request's resolved endpoint URLs.
        services.TryAddScoped<ISignedMetadataProvider, SignedMetadataProvider>();
        return services;
    }
}
