// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Abblix.Oidc.Server.Features.Telemetry;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the dynamic client registration endpoint (RFC 7591).
/// </summary>
internal static class ClientRegistrationEndpointServiceCollectionExtensions
{
    /// <summary>
    /// Registers the registration handler, its validators and processor, and the credentials it issues.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddClientRegistrationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IClientCredentialFactory, ClientCredentialFactory>();
        services.TryAddScoped<IRegistrationAccessTokenService, RegistrationAccessTokenService>();
        services.TryAddScoped<IInitialAccessTokenService, InitialAccessTokenService>();

        services.TryAddScoped<IRegisterClientHandler, RegisterClientHandler>();
        services.Decorate<IRegisterClientHandler, TracedRegisterClientHandler>();
        services.TryAddScoped<IRegisterClientRequestValidator, RegisterClientRequestValidator>();
        services.TryAddKeyedScoped<IRegisterClientRequestValidator, UpdateClientRegistrationValidator>(UpdateClientRequestValidator.RegistrationKey);
        services.TryAddScoped<IRegisterClientRequestProcessor, RegisterClientRequestProcessor>();

        return services;
    }
}
