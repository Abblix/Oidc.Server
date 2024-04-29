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

using Microsoft.AspNetCore.Mvc;
using Core = Abblix.Oidc.Server.Model;
using Parameters = Abblix.Oidc.Server.Model.UserInfoRequest.Parameters;

namespace Abblix.Oidc.Server.Mvc.Model;

/// <summary>
/// Represents a request for user information, extending from <see cref="ClientRequest"/>.
/// This record is used primarily in OpenID Connect to retrieve user profile information from the UserInfo endpoint.
/// </summary>
public record UserInfoRequest
{
    /// <summary>
    /// The access token that the client uses to authenticate and authorize the request to the UserInfo endpoint.
    /// This token represents the user's consent and grants access to their profile information.
    /// </summary>
    [BindProperty(SupportsGet = true, Name = Parameters.AccessToken)]
    public string? AccessToken { get; set; }

    /// <summary>
    /// Maps the properties of this UserInfo request to a <see cref="Core.UserInfoRequest"/> object.
    /// This method is used to translate the request data into a format that can be processed by the core logic of the server,
    /// enabling the retrieval of user profile information.
    /// </summary>
    /// <returns>A <see cref="Core.UserInfoRequest"/> object populated with data from this request.</returns>
    public Core.UserInfoRequest Map() => new() { AccessToken = AccessToken };
}
