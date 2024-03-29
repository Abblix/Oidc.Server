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
