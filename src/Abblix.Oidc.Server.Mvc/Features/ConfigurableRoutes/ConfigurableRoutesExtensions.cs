// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// Reads the endpoint paths from a configuration section written in the form version 2.4 took.
/// </summary>
public static class ConfigurableRoutesExtensions
{
    /// <summary>The word that opens a token in a version 2.4 route template.</summary>
    public const string DefaultPrefix = "route";

    private const string ConnectBase = "base";
    private const string WellKnownBase = "well_known";

    /// <summary>
    /// Sets the paths of <see cref="OidcRouteOptions"/> from a configuration section keyed as in version 2.4.
    /// </summary>
    /// <remarks>
    /// The section names an endpoint by its version 2.4 token (<c>token</c>, <c>introspect</c>, <c>revoke</c>,
    /// <c>par</c>, <c>jwks</c> and the rest), moves every <c>/connect</c> endpoint at once with <c>base</c> and every
    /// <c>/.well-known</c> one with <c>well_known</c>, and may build a value from other tokens, as in
    /// <c>[route:base]/issue</c>. A path starting with <c>~/</c> is taken from the application root. An endpoint the
    /// section says nothing about keeps the path it had, so a path set in code before this call stands.
    /// </remarks>
    /// <param name="services">The service collection the server is registered in.</param>
    /// <param name="configSection">The configuration section holding the paths.</param>
    /// <param name="prefix">The word that opens a token in the section's values, <c>route</c> by default.</param>
    /// <returns>The same service collection, so calls can be chained.</returns>
    public static IServiceCollection ConfigureRoutes(
        this IServiceCollection services,
        IConfigurationSection configSection,
        string prefix = DefaultPrefix)
    {
        services.Configure<OidcRouteOptions>(routes => Apply(new RouteTemplateResolver(prefix, configSection), routes));
        return services;
    }

    private static void Apply(RouteTemplateResolver resolver, OidcRouteOptions routes)
    {
        var connect = resolver.Token(ConnectBase, "~/connect");
        var wellKnown = resolver.Token(WellKnownBase, "~/.well-known");

        void Set(string token, string fallback, Action<string> assign)
        {
            var (path, configured) = resolver.Resolve(resolver.Token(token, fallback));
            if (configured)
                assign(path);
        }

        Set("authorize", connect + "/authorize", path => routes.Authorize = path);
        Set("par", connect + "/par", path => routes.PushedAuthorizationRequest = path);
        Set("userinfo", connect + "/userinfo", path => routes.UserInfo = path);
        Set("endsession", connect + "/endsession", path => routes.EndSession = path);
        Set("checksession", connect + "/checksession", path => routes.CheckSession = path);
        Set("token", connect + "/token", path => routes.Token = path);
        Set("revoke", connect + "/revoke", path => routes.Revocation = path);
        Set("introspect", connect + "/introspect", path => routes.Introspection = path);
        Set("bc_authorize", connect + "/bc-authorize", path => routes.BackChannelAuthentication = path);
        Set("deviceauthorization", connect + "/deviceauthorization", path => routes.DeviceAuthorization = path);
        Set("register", connect + "/register", path =>
        {
            routes.Register = path;
            routes.RegisterClient = $"{path}/{{{OidcRouteOptions.ClientIdRouteParameter}}}";
        });
        Set("configuration", wellKnown + "/openid-configuration", path => routes.Configuration = path);
        Set("oauth_authorization_server", wellKnown + "/oauth-authorization-server",
            path => routes.OAuthAuthorizationServer = path);
        Set("jwks", wellKnown + "/jwks", path => routes.Keys = path);
    }
}
