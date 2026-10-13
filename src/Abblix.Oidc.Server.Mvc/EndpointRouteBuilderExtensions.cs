// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.Controllers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Maps the Abblix OpenID Connect server controllers onto an ASP.NET Core route builder.
/// </summary>
/// <remarks>
/// The controllers of this package carry no route of their own, and a marker route value that no route of the host
/// supplies, so neither <c>MapControllers()</c> nor a conventional route such as <c>{controller}/{action}</c> reaches
/// them. Only the routes mapped here do, and each one is mapped only when its <see cref="OidcEndpoints"/> flag is
/// enabled in <see cref="OidcOptions.EnabledEndpoints"/>, so a disabled endpoint answers 404 to any method and media
/// type, as it does under the Minimal API integration.
/// </remarks>
public static class EndpointRouteBuilderExtensions
{
    private const string ControllerRouteKey = "controller";
    private const string ActionRouteKey = "action";
    private const int AttributeRouteOrder = 0;

    /// <summary>
    /// One route of the library: the endpoint flag that enables it, the path it takes from
    /// <see cref="OidcRouteOptions"/>, the action it reaches and the name it is mapped under.
    /// </summary>
    private sealed record ControllerRoute(
        OidcEndpoints Endpoint,
        Func<OidcRouteOptions, string> Pattern,
        string Controller,
        string Action,
        string Name);

    private static readonly ControllerRoute[] Routes =
    [
        new(OidcEndpoints.Configuration, routes => routes.Configuration,
            MvcUtils.NameOf<DiscoveryController>(), nameof(DiscoveryController.ConfigurationAsync),
            EndpointNames.Configuration),
        new(OidcEndpoints.Configuration, routes => routes.OAuthAuthorizationServer,
            MvcUtils.NameOf<DiscoveryController>(), nameof(DiscoveryController.ConfigurationAsync),
            EndpointNames.OAuthAuthorizationServer),
        new(OidcEndpoints.Keys, routes => routes.Keys,
            MvcUtils.NameOf<DiscoveryController>(), nameof(DiscoveryController.KeysAsync),
            EndpointNames.Keys),

        new(OidcEndpoints.CheckSession, routes => routes.CheckSession,
            MvcUtils.NameOf<AuthenticationController>(), nameof(AuthenticationController.CheckSessionAsync),
            EndpointNames.CheckSession),
        new(OidcEndpoints.Authorize, routes => routes.Authorize,
            MvcUtils.NameOf<AuthenticationController>(), nameof(AuthenticationController.AuthorizeAsync),
            EndpointNames.Authorize),
        new(OidcEndpoints.UserInfo, routes => routes.UserInfo,
            MvcUtils.NameOf<AuthenticationController>(), nameof(AuthenticationController.UserInfoAsync),
            EndpointNames.UserInfo),
        new(OidcEndpoints.EndSession, routes => routes.EndSession,
            MvcUtils.NameOf<AuthenticationController>(), nameof(AuthenticationController.EndSessionAsync),
            EndpointNames.EndSession),

        new(OidcEndpoints.Token, routes => routes.Token,
            MvcUtils.NameOf<TokenController>(), nameof(TokenController.TokenAsync),
            EndpointNames.Token),
        new(OidcEndpoints.Revocation, routes => routes.Revocation,
            MvcUtils.NameOf<TokenController>(), nameof(TokenController.RevocationAsync),
            EndpointNames.Revocation),
        new(OidcEndpoints.Introspection, routes => routes.Introspection,
            MvcUtils.NameOf<TokenController>(), nameof(TokenController.IntrospectionAsync),
            EndpointNames.Introspection),

        new(OidcEndpoints.PushedAuthorizationRequest, routes => routes.PushedAuthorizationRequest,
            MvcUtils.NameOf<BackChannelAuthorizationController>(),
            nameof(BackChannelAuthorizationController.PushAuthorizeAsync),
            EndpointNames.PushedAuthorizationRequest),
        new(OidcEndpoints.BackChannelAuthentication, routes => routes.BackChannelAuthentication,
            MvcUtils.NameOf<BackChannelAuthorizationController>(),
            nameof(BackChannelAuthorizationController.BackChannelAuthenticationAsync),
            EndpointNames.BackChannelAuthentication),
        new(OidcEndpoints.DeviceAuthorization, routes => routes.DeviceAuthorization,
            MvcUtils.NameOf<BackChannelAuthorizationController>(),
            nameof(BackChannelAuthorizationController.DeviceAuthorizationAsync),
            EndpointNames.DeviceAuthorization),

        new(OidcEndpoints.RegisterClient, routes => routes.Register,
            MvcUtils.NameOf<ClientManagementController>(), nameof(ClientManagementController.RegisterClientAsync),
            EndpointNames.Register),
        new(OidcEndpoints.RegisterClient, routes => routes.RegisterClient,
            MvcUtils.NameOf<ClientManagementController>(), nameof(ClientManagementController.ReadClientAsync),
            EndpointNames.RegisterClient),
        new(OidcEndpoints.RegisterClient, routes => routes.RegisterClient,
            MvcUtils.NameOf<ClientManagementController>(), nameof(ClientManagementController.UpdateClientAsync),
            EndpointNames.UpdateClient),
        new(OidcEndpoints.RegisterClient, routes => routes.RegisterClient,
            MvcUtils.NameOf<ClientManagementController>(), nameof(ClientManagementController.RemoveClientAsync),
            EndpointNames.RemoveClient),
    ];

    /// <summary>
    /// Maps the enabled OpenID Connect and OAuth 2.0 endpoints at the paths <see cref="OidcRouteOptions"/> gives them.
    /// </summary>
    /// <remarks>
    /// The routes are added beside the host's own rather than to a route group: MVC gives a route group a source of
    /// endpoints of its own, which would map every attribute-routed controller of the host a second time, under the
    /// group's prefix as well. Mapped beside the host's routes, they share one source with the host's
    /// <c>MapControllers()</c>, which ASP.NET Core also implies for any conventional route, so the host's
    /// attribute-routed controllers are mapped as <c>MapControllers()</c> maps them.
    /// </remarks>
    /// <param name="endpoints">The endpoint route builder to map the endpoints onto.</param>
    /// <param name="prefix">An optional route prefix to mount all OIDC endpoints under (default: none).</param>
    /// <returns>A builder that applies a convention (rate limiting, host filtering, metadata) to every OIDC endpoint
    /// at once, and to no route of the host's.</returns>
    public static IEndpointConventionBuilder MapOidcControllers(this IEndpointRouteBuilder endpoints, string prefix = "")
    {
        // Refuse at startup rather than let both adapters map the same paths and fail on the first request with a
        // routing error that names neither package.
        TransportAdapterConflict.ThrowIfLoaded(
            TransportAdapterConflict.MinimalApiAdapterAssemblyName,
            "Both OIDC transport adapters are present in this application: MapOidcControllers() maps the MVC " +
            "endpoints, and the Minimal API adapter (Abblix.OIDC.Server.MinimalApi) is loaded as well. Only one " +
            "of them may serve the OIDC endpoints, since both map the same paths. " +
            "To stay on MVC, remove the Abblix.OIDC.Server.MinimalApi package reference together with any " +
            "MapOidcEndpoints() call. To stay on Minimal API, remove the Abblix.OIDC.Server.MVC package reference " +
            "together with this MapOidcControllers() call.");

        var enabled = endpoints.ServiceProvider.GetRequiredService<IOptions<OidcOptions>>().Value.EnabledEndpoints;
        var routes = endpoints.ServiceProvider.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        var basePath = prefix.TrimEnd('/');

        // The route name is what OidcEndpointResolver finds the URL by. An endpoint name (WithName) would be copied
        // onto the link-generation entry MVC makes for a named route as well, and refused as a duplicate.
        var mapped = Routes
            .Where(route => enabled.HasFlag(route.Endpoint))
            .Select(route => (IEndpointConventionBuilder)endpoints.MapControllerRoute(
                route.Name,
                basePath + route.Pattern(routes),
                new RouteValueDictionary
                {
                    [ControllerRouteKey] = route.Controller,
                    [ActionRouteKey] = route.Action,
                    [OidcRouteValueAttribute.Key] = OidcRouteValueAttribute.Value,
                }))
            .ToList();

        // MVC orders a conventional route after every attribute route and Minimal API endpoint, and order is
        // compared before how literal a path is, so a host pattern such as /{a}/{b} would take /connect/token. The
        // order attribute routes have puts the library's literal paths back ahead of such a pattern.
        var builder = new OidcControllersConventionBuilder(mapped);
        builder.Add(endpoint =>
        {
            if (endpoint is RouteEndpointBuilder route)
                route.Order = AttributeRouteOrder;
        });
        return builder;
    }
}
