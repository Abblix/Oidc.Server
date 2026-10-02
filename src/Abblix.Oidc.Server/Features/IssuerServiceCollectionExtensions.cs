// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.Issuer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring the issuer.
/// </summary>
public static class IssuerServiceCollectionExtensions
{
    /// <summary>
    /// Configures the issuer provider service to dynamically determine the issuer URI based on application settings.
    /// If an issuer is preconfigured in the options, a preconfigured issuer provider is used.
    /// Otherwise, a request-based issuer provider is utilized to determine the issuer URI dynamically,
    /// allowing for flexible deployment scenarios. The settings belonging to the issuer come from the same options.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the issuer provider to.</param>
    /// <returns>The modified <see cref="IServiceCollection"/> with the issuer provider configured.</returns>
    public static IServiceCollection AddIssuer(this IServiceCollection services)
    {
        services.TryAddSingleton<IIssuerProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<OidcOptions>>().Value;
            return options.Issuer != null
                ? sp.CreateService<PreconfiguredIssuerProvider>()
                : sp.CreateService<RequestBasedIssuerProvider>();
        });
        services.TryAddSingleton<IIssuerSettings, OptionsIssuerSettings>();

        // Transient, so each service holding values gets its own holder
        services.TryAddTransient(typeof(IIssuerLocal<>), typeof(SingleIssuerLocal<>));
        return services;
    }
}
