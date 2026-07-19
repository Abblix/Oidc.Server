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

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client;

/// <summary>
/// Registration entry points for the Abblix OIDC/OAuth client core.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the framework-agnostic core of the Abblix OIDC/OAuth client and binds its options.
    /// </summary>
    /// <param name="services">The service collection the client services are added to.</param>
    /// <param name="configureOptions">A delegate that configures <see cref="OidcClientOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance, so calls can be chained.</returns>
    public static IServiceCollection AddOidcClientCore(
        this IServiceCollection services, Action<OidcClientOptions> configureOptions)
    {
        // Skeleton: options are bound here. Feature services and the composed request and
        // validation pipelines are registered in the following units of the client build-out.
        services.Configure(configureOptions);
        return services;
    }
}
