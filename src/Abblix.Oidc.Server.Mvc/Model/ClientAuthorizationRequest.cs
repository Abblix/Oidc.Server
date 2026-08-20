// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Authorizes permission to manage a client per RFC 7592 Dynamic Client Registration Management Protocol.
/// Identifies the client and provides authentication credentials without dictating the management action.
/// The actual operation (read, update, or delete) is determined by the HTTP verb.
/// </summary>
/// <remarks>
/// Deliberately hand-written rather than generated: it is not a transport mirror of the core
/// client request but a narrow projection of it specific to the management endpoints, where the
/// client identifier travels in the URL path - a routing concept the core deliberately
/// does not know about.
/// </remarks>
public record ClientAuthorizationRequest
{
    /// <summary>
    /// The client identifier from the URL path parameter.
    /// </summary>
    [FromRoute(Name = Path.ClientId)]
    public required string ClientId { get; init; }

    /// <summary>
    /// The registration_access_token from the Authorization header.
    /// Used to authenticate client management operations per RFC 7592.
    /// </summary>
    [FromHeader(Name = HttpRequestHeaders.Authorization)]
    public AuthenticationHeaderValue? AuthorizationHeader { get; init; }

    /// <summary>
    /// Projects the management authorization onto the core client request model.
    /// </summary>
    public Server.Model.ClientRequest ToClientRequest() => new()
    {
        ClientId = ClientId,
        AuthorizationHeader = AuthorizationHeader,
    };

    /// <summary>
    /// Implicit form of <see cref="ToClientRequest"/>, letting the management authorization flow
    /// into any core-typed parameter or variable without an explicit call.
    /// </summary>
    public static implicit operator Server.Model.ClientRequest(ClientAuthorizationRequest request)
        => request.ToClientRequest();
}
