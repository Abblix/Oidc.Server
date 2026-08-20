// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Shared CORS registration for the OIDC transport adapters. Every OIDC endpoint is tagged with the policy
/// name <see cref="OidcConstants.CorsPolicyName"/> (the MVC controllers through <c>[EnableCors]</c>, the
/// Minimal API endpoints through <c>RequireCors</c>); this fills that policy so a browser client can read the
/// endpoints cross-origin out of the box, and leaves the host in full control of it.
/// </summary>
public static class CorsServiceCollectionExtensions
{
    /// <summary>
    /// Registers the CORS services the OIDC endpoints rely on and a default
    /// <see cref="OidcConstants.CorsPolicyName"/> policy built from <see cref="OidcCorsOptions"/> - but only
    /// when the host has not already defined a policy of that name. Idempotent: calling it from more than one
    /// adapter registers the post-configure step once and applies the default a single time.
    /// </summary>
    /// <param name="services">The service collection to add the CORS registration to.</param>
    /// <returns>The same <paramref name="services"/> instance so calls can be chained.</returns>
    public static IServiceCollection AddOidcCors(this IServiceCollection services)
    {
        services.AddCors();

        // Options-pattern set: TryAddEnumerable dedups by implementation type, so a host that composes both
        // the MVC and Minimal API adapters registers this post-configure exactly once.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<CorsOptions>, ConfigureOidcCorsPolicy>());

        return services;
    }
}