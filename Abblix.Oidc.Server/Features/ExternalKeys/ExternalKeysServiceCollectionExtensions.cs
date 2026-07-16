// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Publishes a wired <see cref="IKeyCustodian"/>'s public key halves at the <c>/jwks</c> endpoint. This is the
/// shared half of the Vault and Azure integrations, and the extension point for a host that plugs in its own
/// custodian: register the custodian with <c>AddKeyCustodian</c>, then call this.
/// </summary>
public static class ExternalKeysServiceCollectionExtensions
{
    /// <summary>
    /// Publishes the custodian's public key halves at <c>/jwks</c> (via the generic <see cref="ExternalKeysProvider"/>),
    /// replacing the default key provider. The custodian's private operations are wired into the crypto seams by
    /// <c>AddKeyCustodian</c>. Call this AFTER the custodian registration and AFTER the OIDC registration, for the
    /// last singular registration to win.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configuration">Resolves the key names and algorithms to publish (typically from the custodian's
    /// options).</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddExternalKeys(
        this IServiceCollection services,
        Func<IServiceProvider, ExternalKeyConfiguration> configuration)
    {
        services.ComposeExternalKeyBackends();

        // Construct the provider through the container so the custodian is injected from DI, overriding only the
        // per-call configuration. Replaces the default key provider by the last-singular-wins rule.
        services.AddSingleton<IAuthServiceKeysProvider>(serviceProvider =>
            serviceProvider.CreateService<ExternalKeysProvider>(Dependency.Override(configuration(serviceProvider))));

        return services;
    }
}
