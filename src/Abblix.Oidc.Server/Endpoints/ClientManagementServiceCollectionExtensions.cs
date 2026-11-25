// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the dynamic client registration and management endpoints (RFC 7591, RFC 7592).
/// </summary>
internal static class ClientManagementServiceCollectionExtensions
{
    /// <summary>
    /// Registers services and validators for dynamic client registration and management endpoints,
    /// based on the provided options factory.
    /// </summary>
    /// <remarks>
    /// This method enables the dynamic registration, reading, and removal of OAuth 2.0 clients at runtime,
    /// facilitating flexible and scalable client management.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddDynamicClientEndpoints(this IServiceCollection services)
    {
        services.AddClientRegistrationContextValidators();

        services.TryAddSingleton<IRegistrationAccessTokenValidator, RegistrationAccessTokenValidator>();
        services.TryAddSingleton<IInitialAccessTokenValidator, InitialAccessTokenValidator>();

        // Refuse at startup an offline access for new clients the enumeration does not define, and grant types for
        // them that refuse every registration, which every registration takes and would otherwise fail on
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, NewClientOfflineAccessValidator>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, NewClientGrantTypesValidator>());

        return services
            .AddClientRegistrationEndpoint()
            .AddClientConfigurationEndpoint();
    }

}
