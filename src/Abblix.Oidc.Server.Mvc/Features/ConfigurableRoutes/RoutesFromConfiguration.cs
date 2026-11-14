// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;

/// <summary>
/// What one call of <see cref="ConfigurableRoutesExtensions.ConfigureRoutes"/> sets: the library's endpoint paths
/// in <see cref="OidcRouteOptions"/>, and the convention resolving the tokens in the host's own route templates.
/// </summary>
/// <param name="resolver">Resolves a template's tokens from the configuration section.</param>
internal sealed class RoutesFromConfiguration(RouteTemplateResolver resolver)
    : IConfigureOptions<OidcRouteOptions>, IConfigureOptions<MvcOptions>
{
    private const string ConnectBase = "base";
    private const string WellKnownBase = "well_known";
    private const string ApplicationRoot = "~";
    private const string FromApplicationRoot = "~/";

    /// <inheritdoc />
    public void Configure(MvcOptions options) => options.Conventions.Add(new ConfigurableRouteConvention(resolver));

    /// <summary>Sets every endpoint path the section names, directly or through a base.</summary>
    /// <exception cref="InvalidOperationException">A path the section gives cannot be a route: a token is left
    /// unresolved, or a "~" is not followed by "/".</exception>
    public void Configure(OidcRouteOptions routes)
    {
        var connect = resolver.Token(ConnectBase, "~/connect");
        var wellKnown = resolver.Token(WellKnownBase, "~/.well-known");

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

    private void Set(string token, string fallback, Action<string> assign)
    {
        var (template, configured) = resolver.Resolve(resolver.Token(token, fallback));
        if (configured)
            assign(ToPath(token, template));
    }

    /// <summary>
    /// A resolved template as a route pattern. Version 2.4 wrote a path from the application root as "~/...", which a
    /// pattern spells "/...", and refused anything else it could not route; so does this.
    /// </summary>
    private static string ToPath(string token, string template)
    {
        if (template.Contains('['))
        {
            throw new InvalidOperationException(
                $"The path of the route token '{token}' keeps an unresolved token: '{template}'.");
        }

        if (template.StartsWith(FromApplicationRoot, StringComparison.Ordinal))
            return template[1..];

        if (string.Equals(template, ApplicationRoot, StringComparison.Ordinal))
            return "/";

        if (template.StartsWith(ApplicationRoot, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"The path of the route token '{token}' starts with '~' not followed by '/': '{template}'.");
        }

        return template;
    }
}
