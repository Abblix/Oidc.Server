// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the client configuration endpoint (RFC 7592): reading, updating and removing a registration.
/// </summary>
internal static class ClientConfigurationEndpointServiceCollectionExtensions
{
    /// <summary>
    /// Registers the read, update and remove handlers and the validator of the requests they share.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddClientConfigurationEndpoint(this IServiceCollection services)
    {
        services.TryAddScoped<IClientRequestValidator, ClientRequestValidator>();

        services.TryAddScoped<IReadClientHandler, ReadClientHandler>();
        services.TryAddScoped<IReadClientRequestProcessor, ReadClientRequestProcessor>();

        services.TryAddScoped<IUpdateClientHandler, UpdateClientHandler>();
        services.TryAddScoped<IUpdateClientRequestValidator, UpdateClientRequestValidator>();
        services.TryAddScoped<IUpdateClientRequestProcessor, UpdateClientRequestProcessor>();

        services.TryAddScoped<IRemoveClientHandler, RemoveClientHandler>();
        services.TryAddScoped<IRemoveClientRequestProcessor, RemoveClientRequestProcessor>();

        return services;
    }
}
