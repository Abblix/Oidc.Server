// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.DependencyInjection;

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
        services.AddTelemetryDecorator<IClientRequestValidator, ObservedClientRequestValidator>();

        services.TryAddScoped<IReadClientHandler, ReadClientHandler>();
        services.AddTelemetryDecorator<IReadClientHandler, ObservedReadClientHandler>();
        services.TryAddScoped<IReadClientRequestProcessor, ReadClientRequestProcessor>();
        services.AddTelemetryDecorator<IReadClientRequestProcessor, ObservedReadClientRequestProcessor>();

        services.TryAddScoped<IUpdateClientHandler, UpdateClientHandler>();
        services.AddTelemetryDecorator<IUpdateClientHandler, ObservedUpdateClientHandler>();
        services.TryAddScoped<IUpdateClientRequestValidator, UpdateClientRequestValidator>();
        services.AddTelemetryDecorator<IUpdateClientRequestValidator, ObservedUpdateClientRequestValidator>();
        services.TryAddScoped<IUpdateClientRequestProcessor, UpdateClientRequestProcessor>();
        services.AddTelemetryDecorator<IUpdateClientRequestProcessor, ObservedUpdateClientRequestProcessor>();

        services.TryAddScoped<IRemoveClientHandler, RemoveClientHandler>();
        services.AddTelemetryDecorator<IRemoveClientHandler, ObservedRemoveClientHandler>();
        services.TryAddScoped<IRemoveClientRequestProcessor, RemoveClientRequestProcessor>();
        services.AddTelemetryDecorator<IRemoveClientRequestProcessor, ObservedRemoveClientRequestProcessor>();

        return services;
    }
}
