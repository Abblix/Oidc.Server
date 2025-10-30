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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

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
    /// A <see cref="Task"/> that resolves to a <see cref="Result{UserInfoFoundResponse, AuthError}"/>,
    /// which contains the user information if the request is authorized and valid,
    /// or an error response indicating why the request could not be fulfilled.
    /// </returns>
    /// <remarks>
    /// This method plays a crucial role in the OAuth 2.0 and OIDC ecosystems by enabling secure access to user
    /// information based on authorized requests. Implementations should ensure that the access token provided
    /// in the UserInfo request is validated and that any returned information is consistent with the scopes
    /// granted during the authorization process.
    /// </remarks>
    Task<Result<UserInfoFoundResponse, AuthError>> HandleAsync(
        UserInfoRequest userInfoRequest,
        ClientRequest clientRequest);
}
