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

namespace Abblix.Oidc.Client.Features.IdentityTokens;

/// <summary>
/// Registers the ID Token validator.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the check that decides whether an ID Token may be believed.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">Adjusts the policy where the specification leaves a choice.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddIdentityTokenValidation(
        this IServiceCollection services,
        Action<IdentityTokenValidationOptions>? configure = null)
    {
        // The JOSE layer this delegates the cryptography to. Idempotent, so a host that already
        // registered it for its own use keeps its registration.
        services.AddJsonWebTokens();

        // A soft default, so a test or a host can substitute a clock before this call.
        services.TryAddSingleton(TimeProvider.System);

        if (configure is not null)
            services.Configure(configure);

        services.TryAddSingleton<IIdentityTokenValidator, IdentityTokenValidator>();

        return services;
    }
}
