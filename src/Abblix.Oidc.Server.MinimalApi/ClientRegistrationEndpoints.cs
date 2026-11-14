// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using System.Net.Http.Headers;
using System.Net.Mime;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
using Abblix.Oidc.Server.MinimalApi.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// The endpoints of dynamic client registration (RFC 7591) and management (RFC 7592).
/// </summary>
internal static class ClientRegistrationEndpoints
{
    /// <summary>Maps the enabled endpoints of this area onto the OIDC route group.</summary>
    public static void MapClientRegistrationEndpoints(
        this RouteGroupBuilder oidcGroup, OidcOptions options, OidcRouteOptions routes)
    {
        if (options.EnabledEndpoints.HasFlag(OidcEndpoints.RegisterClient))
        {
            oidcGroup
                .MapPost(routes.Register, RegisterClientAsync)
                .WithName(EndpointNames.Register)
                .Accepts<Core.ClientRegistrationRequest>(MediaTypeNames.Application.Json)
                .BoundBy(options.MaxRegistrationRequestSize);

            oidcGroup
                .MapGet(routes.RegisterClient, ReadClientAsync)
                .WithName(EndpointNames.RegisterClient);

            // The update endpoint (RFC 7592 Section 2.2) binds the same model as registration, ahead of the
            // registration access token check, so it carries the same bound.
            oidcGroup
                .MapPut(routes.RegisterClient, UpdateClientAsync)
                .Accepts<Core.ClientRegistrationRequest>(MediaTypeNames.Application.Json)
                .BoundBy(options.MaxRegistrationRequestSize);

            oidcGroup.MapDelete(routes.RegisterClient, RemoveClientAsync);
        }
    }

    /// <summary>
    /// Registers a new client dynamically (RFC 7591). The metadata is bound from the JSON body; the initial access
    /// token, the only value the body cannot carry, is merged from the Authorization header.
    /// </summary>
    private static async Task<IResult> RegisterClientAsync(
        ClientMetadataBody body,
        HttpContext context,
        [FromServices] IRegisterClientHandler handler,
        [FromServices] IRegisterClientResponseFormatter formatter,
        [FromServices] ITenantAccessor tenantAccessor)
    {
        if (body is not { Request: { } request })
            return body.Refusal!;

        var clientRegistrationRequest = request with { AuthorizationHeader = ParseAuthorizationHeader(context.Request) };
        var response = await handler.HandleAsync(tenantAccessor.CurrentTenant(), clientRegistrationRequest);
        return await formatter.FormatResponseAsync(clientRegistrationRequest, response);
    }

    /// <summary>Reads a registered client's configuration (RFC 7592 section 2.1).</summary>
    private static async Task<IResult> ReadClientAsync(
        ClientAuthorizationRequest authorizationRequest,
        [FromServices] IReadClientHandler handler,
        [FromServices] IReadClientResponseFormatter formatter,
        [FromServices] ITenantAccessor tenantAccessor)
    {
        Core.ClientRequest coreClientRequest = authorizationRequest;
        var response = await handler.HandleAsync(tenantAccessor.CurrentTenant(), coreClientRequest);
        return await formatter.FormatResponseAsync(coreClientRequest, response);
    }

    /// <summary>Updates a registered client's configuration (RFC 7592 section 2.2).</summary>
    private static async Task<IResult> UpdateClientAsync(
        ClientAuthorizationRequest authorizationRequest,
        ClientMetadataBody body,
        [FromServices] IUpdateClientHandler handler,
        [FromServices] IUpdateClientResponseFormatter formatter,
        [FromServices] ITenantAccessor tenantAccessor)
    {
        if (body is not { Request: { } registrationRequest })
            return body.Refusal!;

        var updateRequest = new UpdateClientRequest(authorizationRequest, registrationRequest);
        var response = await handler.HandleAsync(tenantAccessor.CurrentTenant(), updateRequest);
        return await formatter.FormatResponseAsync(updateRequest, response);
    }

    /// <summary>Removes a registered client (RFC 7592 section 2.3).</summary>
    private static async Task<IResult> RemoveClientAsync(
        ClientAuthorizationRequest authorizationRequest,
        [FromServices] IRemoveClientHandler handler,
        [FromServices] IRemoveClientResponseFormatter formatter,
        [FromServices] ITenantAccessor tenantAccessor)
    {
        Core.ClientRequest coreClientRequest = authorizationRequest;
        var response = await handler.HandleAsync(tenantAccessor.CurrentTenant(), coreClientRequest);
        return await formatter.FormatResponseAsync(coreClientRequest, response);
    }

    private static AuthenticationHeaderValue? ParseAuthorizationHeader(HttpRequest request)
    {
        var rawAuthorization = request.Headers.Authorization.ToString();
        return !string.IsNullOrEmpty(rawAuthorization) && AuthenticationHeaderValue.TryParse(rawAuthorization, out var header)
            ? header
            : null;
    }
}
