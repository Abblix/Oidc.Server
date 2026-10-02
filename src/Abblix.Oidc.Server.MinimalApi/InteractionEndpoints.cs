// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.EndSession;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// The endpoints that act for the end user: user info, ending the session, and authorization.
/// </summary>
internal static class InteractionEndpoints
{
    /// <summary>Maps the enabled endpoints of this area onto the OIDC route group.</summary>
    public static void MapInteractionEndpoints(
        this RouteGroupBuilder oidcGroup, OidcOptions options, OidcRouteOptions routes)
    {
        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.UserInfo))
        {
            oidcGroup
                .MapMethods(routes.UserInfo, [HttpMethods.Get, HttpMethods.Post], UserInfoAsync)
                .WithName(EndpointNames.UserInfo)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.EndSession))
        {
            oidcGroup
                .MapMethods(routes.EndSession, [HttpMethods.Get, HttpMethods.Post], EndSessionAsync)
                .WithName(EndpointNames.EndSession)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Authorize))
        {
            oidcGroup
                .MapMethods(routes.Authorize, [HttpMethods.Get, HttpMethods.Post], AuthorizeAsync)
                .WithName(EndpointNames.Authorize);
        }
    }

    /// <summary>
    /// Returns the authenticated end-user's claims (OpenID Connect Core 5.3). The request and the client context are
    /// bound from the query string or the posted form.
    /// </summary>
    private static async Task<IResult> UserInfoAsync(
        UserInfoRequest userInfoRequest,
        ClientRequest clientRequest,
        IUserInfoHandler handler,
        IUserInfoResponseFormatter formatter)
    {
        Core.UserInfoRequest coreUserInfoRequest = userInfoRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreUserInfoRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreUserInfoRequest, response);
    }

    /// <summary>
    /// Ends the user's session (OpenID Connect RP-Initiated Logout). The request is bound from the query string or the
    /// posted form.
    /// </summary>
    private static async Task<IResult> EndSessionAsync(
        EndSessionRequest endSessionRequest,
        IEndSessionHandler handler,
        IEndSessionResponseFormatter formatter)
    {
        Core.EndSessionRequest coreEndSessionRequest = endSessionRequest;
        var response = await handler.HandleAsync(coreEndSessionRequest);
        return await formatter.FormatResponseAsync(coreEndSessionRequest, response);
    }

    /// <summary>
    /// Handles the authorization request (OpenID Connect Core 3.1). The request is bound from the query string or the
    /// posted form, and the response is delivered to the client's redirect URI or an interaction page.
    /// </summary>
    private static async Task<IResult> AuthorizeAsync(
        AuthorizationRequest authorizationRequest,
        IAuthorizationHandler handler,
        IAuthorizationResponseFormatter formatter)
    {
        Core.AuthorizationRequest coreAuthorizationRequest = authorizationRequest;
        var response = await handler.HandleAsync(coreAuthorizationRequest);
        return await formatter.FormatResponseAsync(coreAuthorizationRequest, response);
    }
}
