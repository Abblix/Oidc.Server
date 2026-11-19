// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Endpoints;

/// <summary>
/// Registers the validation pipeline every dynamic client registration passes through.
/// </summary>
internal static class ClientRegistrationValidationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the client registration context validators and composes them, in order, into one validator.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>.</returns>
    internal static IServiceCollection AddClientRegistrationContextValidators(this IServiceCollection services)
    {
        // compose ClientRegistrationContext validation as a pipeline of several IClientRegistrationContextValidator:
        // the checks of the request itself first, then those of the metadata it carries
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, InitialAccessTokenContextValidator>(),
            // Before the check that the client_id is free, which would fetch the document a URL names
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ClientIdentifierUrlRegistrationValidator>(),
            ServiceDescriptor.Singleton<IClientRegistrationContextValidator, ClientIdValidator>(),
            ..ClientRegistrationMetadataChecks.All,
        ]);
        return services.Compose<IClientRegistrationContextValidator, ClientRegistrationContextValidatorComposite>();
    }
}
