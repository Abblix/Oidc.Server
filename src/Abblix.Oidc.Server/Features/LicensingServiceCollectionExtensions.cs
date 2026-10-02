// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.Licensing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring licensing.
/// </summary>
public static class LicensingServiceCollectionExtensions
{
    /// <summary>
    /// Registers the license JWT provider using options configuration to obtain the license JWT.
    /// </summary>
    /// <remarks>
    /// This method configures the OIDC service's licensing by using the <see cref="OptionsLicenseJwtProvider"/>,
    /// which retrieves the license JWT from application settings or options. It's suitable for scenarios where
    /// the license JWT is configured through application settings (e.g., appsettings.json or environment variables).
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the license provider to.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further configurations.</returns>
    public static IServiceCollection AddLicenseFromOptions(this IServiceCollection services)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, LicenseLoadingService>());
        services.TryAddSingleton<ILicenseJwtProvider, OptionsLicenseJwtProvider>();

        // The hosted service evaluates the loaded licenses against this clock. Registered here rather than
        // relied upon from elsewhere: this method is public and a host may call it on a collection that has
        // nothing else of ours in it, where the missing registration surfaces at BuildServiceProvider as a
        // failure to activate a type whose name says nothing about licensing.
        services.TryAddSingleton(TimeProvider.System);
        return services;
    }

    /// <summary>
    /// Registers the license JWT provider using a provided static license JWT string.
    /// </summary>
    /// <remarks>
    /// This method allows for direct specification of the license JWT, bypassing options configuration.
    /// It utilizes the <see cref="StaticLicenseJwtProvider"/> to supply the license JWT directly to the OIDC service.
    /// This approach is particularly useful in scenarios where the license JWT is obtained programmatically or from
    /// external sources not tied to the application's static configuration.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the license provider to.</param>
    /// <param name="licenseJwt">The license JWT string to be used for OIDC service configuration validation.</param>
    /// <returns>The <see cref="IServiceCollection"/> for chaining further configurations.</returns>
    public static IServiceCollection AddLicense(this IServiceCollection services, string licenseJwt)
    {
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, LicenseLoadingService>());
        // Intentional replacement: AddLicense(jwt) is an explicit host opt-in that must override
        // any ILicenseJwtProvider previously registered by AddLicenseFromOptions.
        services.Replace(ServiceDescriptor.Singleton<ILicenseJwtProvider>(
            sp => sp.CreateService<StaticLicenseJwtProvider>(Dependency.Override(licenseJwt))));

        // See AddLicenseFromOptions: the hosted service needs a clock, and this method is equally reachable
        // on a collection carrying nothing else of ours.
        services.TryAddSingleton(TimeProvider.System);
        return services;
    }
}
