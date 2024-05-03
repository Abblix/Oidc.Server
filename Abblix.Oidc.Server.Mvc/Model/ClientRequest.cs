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
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.ClientRequest.Parameters;
using HttpRequestHeaders = Abblix.Oidc.Server.Common.Constants.HttpRequestHeaders;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents an abstract model of a request made by a client via server-to-server call.
/// Contains all headers and properties that can be used for authentication in various possible ways.
/// This model captures essential information required for authenticating client requests in server-to-server interactions.
/// </summary>
public record ClientRequest
{
    /// <summary>
    /// The authorization header value, typically containing credentials to authenticate the client to the server.
    /// This header is used in standard HTTP authentication schemes like Basic, Bearer, etc.
    /// </summary>
    [ModelBinder(typeof(AuthenticationHeaderBinder), Name = HttpRequestHeaders.Authorization)]
    public AuthenticationHeaderValue? AuthorizationHeader { get; set; }

    /// <summary>
    /// The client identifier issued to the client during the registration process.
    /// This identifier is unique to the client and is used in conjunction with the client secret to authenticate the client.
    /// </summary>
    [BindProperty(Name = Parameters.ClientId)]
    public string? ClientId { get; set; }

    /// <summary>
    /// The client secret that is known only to the client and the authorization server.
    /// It is used in combination with the client ID to authenticate the client.
    /// </summary>
    [BindProperty(Name = Parameters.ClientSecret)]
    public string? ClientSecret { get; set; }

    /// <summary>
    /// The type of assertion being used for client authentication.
    /// This property specifies the format of the client assertion used for authentication, such as JWT or SAML.
    /// </summary>
    [BindProperty(Name = Parameters.ClientAssertionType)]
    public string? ClientAssertionType { get; set; }

    /// <summary>
    /// The assertion that the client uses for authentication.
    /// This property contains the actual assertion data, usually a digitally signed token, validating the client's identity.
    /// </summary>
    [BindProperty(Name = Parameters.ClientAssertion)]
    public string? ClientAssertion { get; set; }

    /// <summary>
    /// Maps the properties of this client request to a <see cref="Core.ClientRequest"/> object.
    /// This method is used to translate the request data into a format that can be processed by the core logic of the server.
    /// </summary>
    /// <returns>A <see cref="Core.ClientRequest"/> object populated with data from this request.</returns>
    public Core.ClientRequest Map()
    {
        return new Core.ClientRequest
        {
            AuthorizationHeader = AuthorizationHeader,

            ClientId = ClientId,
            ClientSecret = ClientSecret,

            ClientAssertionType = ClientAssertionType,
            ClientAssertion = ClientAssertion
        };
    }
}
