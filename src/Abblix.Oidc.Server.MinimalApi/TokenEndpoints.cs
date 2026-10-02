// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Endpoints.Revocation.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// The endpoints that issue tokens, revoke them and answer what a token is.
/// </summary>
internal static class TokenEndpoints
{
    /// <summary>Maps the enabled endpoints of this area onto the OIDC route group.</summary>
    public static void MapTokenEndpoints(
        this RouteGroupBuilder oidcGroup, OidcOptions options, OidcRouteOptions routes)
    {
        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Token))
        {
            oidcGroup
                .MapPost(routes.Token, TokenAsync)
                .WithName(EndpointNames.Token)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Revocation))
        {
            oidcGroup
                .MapPost(routes.Revocation, RevocationAsync)
                .WithName(EndpointNames.Revocation)
                .RequireCors(OidcConstants.CorsPolicyName);
        }

        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.Introspection))
        {
            oidcGroup
                .MapPost(routes.Introspection, IntrospectionAsync)
                .WithName(EndpointNames.Introspection);
        }
    }

    /// <summary>
    /// Issues tokens (OpenID Connect Core 3.1.3, OAuth 2.0 RFC 6749 section 3.2). The request and the client-authentication
    /// context are each bound from the posted form via their own <c>BindAsync</c>.
    /// </summary>
    private static async Task<IResult> TokenAsync(
        TokenRequest tokenRequest,
        ClientRequest clientRequest,
        ITokenHandler handler,
        ITokenResponseFormatter formatter,
        CancellationToken cancellationToken)
    {
        Core.TokenRequest coreTokenRequest = tokenRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        // Minimal API binds this parameter to the request's own RequestAborted. CIBA holds this call open for
        // the long-polling window, so without it a client that disconnects leaves the server polling storage.
        var response = await handler.HandleAsync(coreTokenRequest, coreClientRequest, cancellationToken);
        return await formatter.FormatResponseAsync(coreTokenRequest, response);
    }

    /// <summary>Revokes a token (RFC 7009). Request and client context are each bound from the posted form.</summary>
    private static async Task<IResult> RevocationAsync(
        RevocationRequest revocationRequest,
        ClientRequest clientRequest,
        IRevocationHandler handler,
        IRevocationResponseFormatter formatter)
    {
        Core.RevocationRequest coreRevocationRequest = revocationRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreRevocationRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreRevocationRequest, response);
    }

    /// <summary>Introspects a token (RFC 7662). Request and client context are each bound from the posted form.</summary>
    private static async Task<IResult> IntrospectionAsync(
        IntrospectionRequest introspectionRequest,
        ClientRequest clientRequest,
        IIntrospectionHandler handler,
        IIntrospectionResponseFormatter formatter)
    {
        Core.IntrospectionRequest coreIntrospectionRequest = introspectionRequest;
        Core.ClientRequest coreClientRequest = clientRequest;
        var response = await handler.HandleAsync(coreIntrospectionRequest, coreClientRequest);
        return await formatter.FormatResponseAsync(coreIntrospectionRequest, response);
    }
}
