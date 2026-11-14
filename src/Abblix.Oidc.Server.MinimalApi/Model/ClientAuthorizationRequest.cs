// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
using Microsoft.AspNetCore.Http;
using Core = Abblix.Oidc.Server.Model;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.MinimalApi.Model;

/// <summary>
/// Authorizes a client-management operation (RFC 7592): the client identifier travels in the URL path and the
/// registration access token in the <c>Authorization</c> header. The HTTP verb decides the operation.
/// </summary>
public sealed record ClientAuthorizationRequest
{
    /// <summary>The client identifier from the <c>{clientId}</c> route parameter.</summary>
    public required string ClientId { get; init; }

    /// <summary>Every line of the <c>Authorization</c> header, carrying the registration access token.</summary>
    public IReadOnlyList<string>? AuthorizationHeaderLines { get; init; }

    /// <summary>Binds the model from the route value and the <c>Authorization</c> header.</summary>
    public static ValueTask<ClientAuthorizationRequest?> BindAsync(HttpContext context)
    {
        var clientId = context.Request.RouteValues.TryGetValue(OidcRouteOptions.ClientIdRouteParameter, out var value)
            ? value?.ToString() ?? string.Empty
            : string.Empty;

        return ValueTask.FromResult<ClientAuthorizationRequest?>(new ClientAuthorizationRequest
        {
            ClientId = clientId,
            AuthorizationHeaderLines = FormValues.HeaderLines(context.Request, HttpRequestHeaders.Authorization),
        });
    }

    /// <summary>Projects the management authorization onto the core client request model.</summary>
    public static implicit operator Core.ClientRequest(ClientAuthorizationRequest request) => new()
    {
        ClientId = request.ClientId,
        AuthorizationHeaderLines = request.AuthorizationHeaderLines,
    };
}
