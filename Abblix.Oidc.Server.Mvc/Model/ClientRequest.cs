// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
