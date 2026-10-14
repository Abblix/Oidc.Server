// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// Reads route tokens such as <c>[route:token?Fallback]</c> from a configuration section, as version 2.4 did.
/// </summary>
public static class ConfigurableRoutesExtensions
{
    /// <summary>The word that opens a token in a version 2.4 route template.</summary>
    public const string DefaultPrefix = "route";

    /// <summary>
    /// Resolves route tokens from a configuration section keyed as in version 2.4: the paths of the library's
    /// endpoints, and the tokens in the host's own attribute route templates.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The section names a library endpoint by its token (<c>token</c>, <c>introspect</c>, <c>revoke</c>,
    /// <c>par</c>, <c>jwks</c> and the rest), moves every <c>/connect</c> endpoint at once with <c>base</c> and every
    /// <c>/.well-known</c> one with <c>well_known</c>, and may build a value from other tokens, as in
    /// <c>[route:base]/issue</c>. A leading <c>~/</c> is read as <c>/</c>; the prefix given to
    /// <see cref="EndpointRouteBuilderExtensions.MapOidcControllers"/> still comes before every path. An endpoint the
    /// section says nothing about keeps the path it had, so a path set in code before this call stands.
    /// </para>
    /// <para>
    /// A host's own controller may carry tokens too, as in <c>[Route("[route:ApiPrefix?v1]/users")]</c> with
    /// <c>"ApiPrefix": "v2"</c> in the section; the convention resolving them is added to <c>MvcOptions</c> and
    /// changes no template without a token. A later call replaces an earlier one.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection the server is registered in.</param>
    /// <param name="configSection">The configuration section holding the token values.</param>
    /// <param name="prefix">The word that opens a token, <c>route</c> by default.</param>
    /// <returns>The same service collection, so calls can be chained.</returns>
    public static IServiceCollection ConfigureRoutes(
        this IServiceCollection services,
        IConfigurationSection configSection,
        string prefix = DefaultPrefix)
    {
        var earlier = services.Where(descriptor => descriptor.ImplementationInstance is RoutesFromConfiguration).ToList();
        foreach (var descriptor in earlier)
            services.Remove(descriptor);

        var routes = new RoutesFromConfiguration(new RouteTemplateResolver(prefix, configSection));
        services.AddOptions();
        services.AddSingleton<IConfigureOptions<OidcRouteOptions>>(routes);
        services.AddSingleton<IConfigureOptions<MvcOptions>>(routes);
        return services;
    }
}
