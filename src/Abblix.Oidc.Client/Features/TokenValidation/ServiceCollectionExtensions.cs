// Abblix OIDC Client Library
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


using Abblix.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.TokenValidation;

/// <summary>
/// Registers the verifier every token from the provider passes through.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the verifier of tokens the provider signed for this client, and the policy it applies.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configureOptions">
    /// A delegate that configures <see cref="ProviderTokenValidationOptions"/>. Optional: the defaults are
    /// usable, and every feature that needs the verifier registers it this way.
    /// </param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddProviderTokenValidation(
        this IServiceCollection services, Action<ProviderTokenValidationOptions>? configureOptions = null)
    {
        if (configureOptions is not null)
            services.Configure(configureOptions);

        services.AddJsonWebTokens();
        services.TryAddSingleton<IProviderTokenVerifier, ProviderTokenVerifier>();

        return services;
    }
}
