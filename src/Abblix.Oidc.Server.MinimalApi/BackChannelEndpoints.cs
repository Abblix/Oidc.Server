// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.PushedAuthorization.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// The authorization requests a client sends to the server directly rather than through the user's browser:
/// pushed authorization requests, client-initiated backchannel authentication (CIBA) and the device
/// authorization grant.
/// </summary>
internal static class BackChannelEndpoints
{
    /// <summary>Maps the enabled endpoints of this area onto the OIDC route group.</summary>
    public static void MapBackChannelEndpoints(
        this RouteGroupBuilder oidcGroup, OidcOptions options, OidcRouteOptions routes)
    {
        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.PushedAuthorizationRequest))
        {
            oidcGroup
                .MapPost(routes.PushedAuthorizationRequest, PushedAuthorizationAsync)
                .WithName(EndpointNames.PushedAuthorizationRequest);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.BackChannelAuthentication))
        {
            oidcGroup
                .MapPost(routes.BackChannelAuthentication, BackChannelAuthenticationAsync)
                .WithName(EndpointNames.BackChannelAuthentication);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.DeviceAuthorization))
        {
            oidcGroup
                .MapPost(routes.DeviceAuthorization, DeviceAuthorizationAsync)
                .WithName(EndpointNames.DeviceAuthorization);
        }
    }

    /// <summary>
    /// Pushes an authorization request (RFC 9126). The authorization request and the client context are each bound
    /// from the posted form.
    /// </summary>
    private static async Task<IResult> PushedAuthorizationAsync(
        AuthorizationRequest authorizationRequest,
        ClientRequest clientRequest,
        IPushedAuthorizationHandler handler,
        IPushedAuthorizationResponseFormatter formatter)
    {
        Core.AuthorizationRequest coreAuthorizationRequest = authorizationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreAuthorizationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreAuthorizationRequest, response);
    }

    /// <summary>
    /// Initiates a CIBA backchannel authentication request (OpenID Connect CIBA section 7). The request and the
    /// client-authentication context are each bound from the posted form.
    /// </summary>
    private static async Task<IResult> BackChannelAuthenticationAsync(
        BackChannelAuthenticationRequest authenticationRequest,
        ClientRequest clientRequest,
        IBackChannelAuthenticationHandler handler,
        IBackChannelAuthenticationResponseFormatter formatter)
    {
        Core.BackChannelAuthenticationRequest coreAuthenticationRequest = authenticationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreAuthenticationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreAuthenticationRequest, coreClientRequest, response);
    }

    /// <summary>
    /// Starts the device authorization grant (RFC 8628). The request and the client-authentication context are each
    /// bound from the posted form.
    /// </summary>
    private static async Task<IResult> DeviceAuthorizationAsync(
        DeviceAuthorizationRequest deviceAuthorizationRequest,
        ClientRequest clientRequest,
        IDeviceAuthorizationHandler handler,
        IDeviceAuthorizationResponseFormatter formatter)
    {
        Core.DeviceAuthorizationRequest coreDeviceAuthorizationRequest = deviceAuthorizationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreDeviceAuthorizationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreDeviceAuthorizationRequest, response);
    }
}
