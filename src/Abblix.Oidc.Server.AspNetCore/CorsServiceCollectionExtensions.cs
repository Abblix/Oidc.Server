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