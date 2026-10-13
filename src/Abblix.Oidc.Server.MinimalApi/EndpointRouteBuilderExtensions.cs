// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Maps the Abblix OpenID Connect server endpoints onto an ASP.NET Core Minimal API route builder.
/// </summary>
/// <remarks>
/// This is the Minimal API counterpart of the MVC integration's <c>app.MapOidcControllers()</c>. Each endpoint is
/// mapped only when its <see cref="OidcEndpoints"/> flag is enabled in <see cref="OidcOptions.EnabledEndpoints"/>, so a
/// disabled endpoint is never registered and answers 404.
/// </remarks>
public static class EndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the enabled OpenID Connect and OAuth 2.0 endpoints onto the route builder and returns it so the host can
    /// continue configuring its own routes.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder to map the endpoints onto.</param>
    /// <param name="prefix">An optional route prefix to mount all OIDC endpoints under (default: none).</param>
    /// <returns>The <see cref="RouteGroupBuilder"/> the OIDC endpoints were mapped onto, so the host can apply
    /// cross-cutting conventions (rate limiting, host filtering, metadata) to all of them at once.</returns>
    public static RouteGroupBuilder MapOidcEndpoints(this IEndpointRouteBuilder endpoints, string prefix = "")
    {
        // Refuse at startup rather than let both adapters map the same paths under the same endpoint names and fail
        // on every request with a routing error that names neither package.
        TransportAdapterConflict.ThrowIfLoaded(
            TransportAdapterConflict.MvcAdapterAssemblyName,
            "Both OIDC transport adapters are present in this application: MapOidcEndpoints() maps the " +
            "Minimal API endpoints, and the MVC adapter (Abblix.OIDC.Server.MVC) is loaded as well. Only one " +
            "of them may serve the OIDC endpoints, since both map the same paths under the same endpoint names. " +
            "To stay on Minimal API, remove the Abblix.OIDC.Server.MVC package reference together with any " +
            "AddOidcServices(), AddOidcMvc() or MapOidcControllers() call. To stay on MVC, remove the " +
            "Abblix.OIDC.Server.MinimalApi package reference together with this MapOidcEndpoints() call.");

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<OidcOptions>>().Value;
        var routes = endpoints.ServiceProvider.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        var oidcGroup = endpoints.MapGroup(prefix).AddOidcEndpointFilters();

        // Each feature area maps only the endpoints enabled in OidcOptions.EnabledEndpoints, so a disabled
        // endpoint is never registered and answers 404, as it does under MVC.
        oidcGroup.MapDiscoveryEndpoints(options, routes);
        oidcGroup.MapTokenEndpoints(options, routes);
        oidcGroup.MapBackChannelEndpoints(options, routes);
        oidcGroup.MapInteractionEndpoints(options, routes);
        oidcGroup.MapClientRegistrationEndpoints(options, routes);

        return oidcGroup;
    }
}
