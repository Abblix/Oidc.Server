// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Http;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi.Model;

/// <summary>
/// Authorizes a client-management operation (RFC 7592): the client identifier travels in the URL path and the
/// registration access token in the <c>Authorization</c> header. The HTTP verb decides the operation.
/// </summary>
public sealed record ClientAuthorizationRequest
{
    /// <summary>The client identifier from the <c>{clientId}</c> route parameter.</summary>
    public required string ClientId { get; init; }

    /// <summary>The registration access token from the <c>Authorization</c> header.</summary>
    public AuthenticationHeaderValue? AuthorizationHeader { get; init; }

    /// <summary>Binds the model from the route value and the <c>Authorization</c> header.</summary>
    public static ValueTask<ClientAuthorizationRequest?> BindAsync(HttpContext context)
    {
        var clientId = context.Request.RouteValues.TryGetValue("clientId", out var value)
            ? value?.ToString() ?? string.Empty
            : string.Empty;

        AuthenticationHeaderValue? authorizationHeader = null;
        var rawAuthorization = context.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(rawAuthorization))
            AuthenticationHeaderValue.TryParse(rawAuthorization, out authorizationHeader);

        return ValueTask.FromResult<ClientAuthorizationRequest?>(new ClientAuthorizationRequest
        {
            ClientId = clientId,
            AuthorizationHeader = authorizationHeader,
        });
    }

    /// <summary>Projects the management authorization onto the core client request model.</summary>
    public static implicit operator Core.ClientRequest(ClientAuthorizationRequest request) => new()
    {
        ClientId = request.ClientId,
        AuthorizationHeader = request.AuthorizationHeader,
    };
}
