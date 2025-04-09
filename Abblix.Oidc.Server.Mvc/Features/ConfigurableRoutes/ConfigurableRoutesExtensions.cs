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

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// Provides extension methods for enabling support for tokenized route templates like
/// <c>[route:MyToken?Fallback]</c> in ASP.NET Core controllers.
/// </summary>
public static class ConfigurableRoutesExtensions
{
    /// <summary>
    /// Enables the resolution of route tokens such as <c>[route:MyToken?Fallback]</c> using values from the specified
    /// configuration section.
    /// </summary>
    /// <param name="services">The service collection to register services with.</param>
    /// <param name="configSection">The configuration section that contains token-to-value mappings.</param>
    /// <param name="prefix">
    /// The token prefix used in route templates. Defaults to <c>"route"</c>, which supports templates like
    /// <c>[route:MyToken?Fallback]</c>.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> instance to support method chaining.</returns>
    /// <remarks>
    /// This method allows route templates in controllers to include tokens that are dynamically resolved
    /// at application startup using values from configuration. If a token is not found, an optional fallback
    /// value can be specified using the <c>?</c> delimiter.
    ///
    /// Example:
    /// <code>
    /// [Route("[route:ApiPrefix?v1]/users")]
    /// public class UsersController : ControllerBase { ... }
    /// </code>
    ///
    /// With configuration:
    /// <code>
    /// "Routes": {
    ///   "ApiPrefix": "v2"
    /// }
    /// </code>
    /// The resulting route will be <c>v2/users</c>. If "ApiPrefix" is not configured, it falls back to <c>v1</c>.
    /// </remarks>
    public static IServiceCollection ConfigureRoutes(
        this IServiceCollection services,
        IConfigurationSection configSection,
        string prefix = Path.RoutePrefix)
    {
        services.Configure<MvcOptions>(options =>
        {
            options.Conventions.Add(new ConfigurableRouteConvention(prefix, configSection));
        });

        return services;
    }

    /// <summary>
    /// Registers a fallback-only route token resolution convention that uses only the fallback values
    /// specified in templates like <c>[route:MyToken?Fallback]</c>, ignoring configuration.
    /// </summary>
    /// <param name="services">The service collection to register services with.</param>
    /// <param name="prefix">
    /// The token prefix used in route templates. Defaults to <c>"route"</c>, which supports templates like
    /// <c>[route:MyToken?Fallback]</c>.
    /// </param>
    /// <returns>The same <see cref="IServiceCollection"/> instance to support method chaining.</returns>
    /// <remarks>
    /// This method ensures that route tokens are resolved to fallback values even if the consumer
    /// of the component does not explicitly provide a configuration section.
    /// </remarks>
    public static IServiceCollection ConfigureRoutesFallback(
        this IServiceCollection services,
        string prefix = Path.RoutePrefix)
    {
        services.PostConfigure<MvcOptions>(options =>
        {
            options.Conventions.Add(new ConfigurableRouteConvention(prefix));
        });

        return services;
    }
}
