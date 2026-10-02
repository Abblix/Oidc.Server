// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.CheckSession.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// The endpoints a client reads to learn about the provider: the discovery document, the published keys,
/// and the session-management frame.
/// </summary>
internal static class DiscoveryEndpoints
{
    /// <summary>Maps the enabled endpoints of this area onto the OIDC route group.</summary>
    public static void MapDiscoveryEndpoints(
        this RouteGroupBuilder oidcGroup, OidcOptions options, OidcRouteOptions routes)
    {
        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Configuration))
        {
            oidcGroup
                .MapGet(routes.Configuration, ConfigurationAsync)
                .WithName(EndpointNames.Configuration)
                .RequireCors(OidcConstants.CorsPolicyName);

            // RFC 8414 section 3: the same Authorization Server Metadata document, also served at the
            // oauth-authorization-server suffix so a client that queries only that suffix still resolves it.
            oidcGroup
                .MapGet(routes.OAuthAuthorizationServer, ConfigurationAsync)
                .WithName(EndpointNames.OAuthAuthorizationServer)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Keys))
        {
            oidcGroup
                .MapGet(routes.Keys, KeysAsync)
                .WithName(EndpointNames.Keys)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.CheckSession))
        {
            oidcGroup
                .MapGet(routes.CheckSession, CheckSessionAsync)
                .WithName(EndpointNames.CheckSession)
                .RequireCors(OidcConstants.CorsPolicyName);
        }
    }

    /// <summary>
    /// Returns the session-management iframe document (OpenID Connect Session Management).
    /// </summary>
    private static async Task<IResult> CheckSessionAsync(
        ICheckSessionHandler handler, ICheckSessionResponseFormatter formatter)
    {
        var response = await handler.HandleAsync();
        return await formatter.FormatResponseAsync(response);
    }

    /// <summary>
    /// Returns the OpenID Provider configuration document (discovery metadata) for the current request.
    /// </summary>
    private static async Task<IResult> ConfigurationAsync(
        IConfigurationHandler handler, IConfigurationResponseFormatter formatter)
    {
        var response = await handler.HandleAsync();
        return await formatter.FormatResponseAsync(response);
    }

    /// <summary>
    /// Returns the JSON Web Key Set (JWKS) with the provider's public signing keys, used by clients to verify
    /// issued tokens.
    /// </summary>
    private static async Task<IResult> KeysAsync(
        IAuthServiceKeysProvider serviceKeysProvider,
        IOptions<OidcOptions> options,
        HttpResponse response,
        ILogger<IAuthServiceKeysProvider> logger)
    {
        var keys = await serviceKeysProvider.GetPublishedKeysAsync(logger);

        // The JWKS is public, cacheable metadata: advertise a lifetime equal to the key-rollover propagation
        // window, overriding the group-wide no-cache policy (SetCacheableHeaders clears the Pragma/Expires the
        // no-cache filter set) for this one endpoint.
        response.SetCacheableHeaders(options.Value.KeyRolloverPropagation);

        return Results.Json(new JsonWebKeySet(keys));
    }
}
