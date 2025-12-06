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
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.AspNetCore.Mvc;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Authorizes permission to manage a client per RFC 7592 Dynamic Client Registration Management Protocol.
/// Identifies the client and provides authentication credentials without dictating the management action.
/// The actual operation (read, update, or delete) is determined by the HTTP verb.
/// </summary>
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
    /// Maps this request to the core ClientRequest model.
    /// </summary>
    public Server.Model.ClientRequest ToClientRequest() => new()
    {
        ClientId = ClientId,
        AuthorizationHeader = AuthorizationHeader,
    };
}
