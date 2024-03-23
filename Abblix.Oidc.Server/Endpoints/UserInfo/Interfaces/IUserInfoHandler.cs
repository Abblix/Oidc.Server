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

using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Defines a contract for handling UserInfo requests within an OAuth 2.0 and OpenID Connect framework.
/// It outlines the necessary operations for processing such requests, ensuring they adhere to security
/// and protocol standards.
/// </summary>
public interface IUserInfoHandler
{
    /// <summary>
    /// Asynchronously handles a UserInfo request, validating the request for authorization and processing it to
    /// return the requested user information.
    /// </summary>
    /// <param name="userInfoRequest">The user info request containing the access token and possibly other parameters
    /// defining the scope of information requested.</param>
    /// <param name="clientRequest">Additional client-specific request information that may be necessary for processing
    /// the request in certain contexts.</param>
    /// <returns>
    /// A <see cref="Task"/> that resolves to a <see cref="UserInfoResponse"/>, which contains the user information
    /// if the request is authorized and valid, or an error response indicating why the request could not be fulfilled.
    /// </returns>
    /// <remarks>
    /// This method plays a crucial role in the OAuth 2.0 and OIDC ecosystems by enabling secure access to user
    /// information based on authorized requests. Implementations should ensure that the access token provided
    /// in the UserInfo request is validated and that any returned information is consistent with the scopes
    /// granted during the authorization process.
    /// </remarks>
    Task<UserInfoResponse> HandleAsync(
        UserInfoRequest userInfoRequest,
        ClientRequest clientRequest);
}
