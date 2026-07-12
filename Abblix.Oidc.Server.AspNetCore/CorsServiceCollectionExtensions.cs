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
    /// <see cref="OidcConstants.CorsPolicyName"/> policy built from <see cref="OidcCorsOptions"/> — but only
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

/// <summary>
/// Fills the OIDC CORS policy after every host <c>Configure&lt;CorsOptions&gt;</c> delegate has run, so a
/// host-defined policy of the same name is never overwritten: the default only fills the gap when the host
/// stays silent. This is what lets a host override the policy in any registration order, with either adapter.
/// </summary>
internal sealed class ConfigureOidcCorsPolicy(IOptions<OidcCorsOptions> corsOptions)
    : IPostConfigureOptions<CorsOptions>
{
    public void PostConfigure(string? name, CorsOptions options)
    {
        // The OIDC policy is global, so it belongs on the default CorsOptions instance. Skip named variants,
        // and skip entirely when the host has already defined a policy of this name (host wins).
        if (name != Options.DefaultName || options.GetPolicy(OidcConstants.CorsPolicyName) is not null)
            return;

        var allowedOrigins = corsOptions.Value.AllowedOrigins;
        options.AddPolicy(OidcConstants.CorsPolicyName, policy =>
        {
            // No configured origins means public read access: the browser sends no credentials, so any origin
            // may read the metadata, token and userinfo responses. A configured list narrows it to those hosts.
            if (allowedOrigins.Count == 0)
                policy.AllowAnyOrigin();
            else
                policy.WithOrigins(allowedOrigins.ToArray());

            policy.AllowAnyHeader().AllowAnyMethod();
        });
    }
}
