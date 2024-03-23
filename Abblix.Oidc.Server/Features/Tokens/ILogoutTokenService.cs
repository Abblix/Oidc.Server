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

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Provides functionality for generating logout tokens as part of the OpenID Connect back-channel logout process.
/// Logout tokens are used to notify clients about the logout event of an authenticated user session.
/// </summary>
public interface ILogoutTokenService
{
    /// <summary>
    /// Asynchronously generates a logout token that encapsulates information about a user's logout event.
    /// This token is sent to clients to initiate the back-channel logout process, enabling them to clean up
    /// user sessions in accordance with the OpenID Connect back-channel logout specification.
    /// </summary>
    /// <param name="clientInfo">Details about the client application that will receive the logout token. This includes
    ///     the client's identifier and other relevant configuration settings that may affect the token generation process.
    /// </param>
    /// <param name="logoutContext">Contextual information related to the logout event, such as the user's identifier
    ///     (sub) and the session identifier (sid) that uniquely identifies the session being logged out.
    ///     Additional information about the logout event, such as the reason for logout, can also be included if supported
    ///     by the implementation.</param>
    /// <returns>A task that represents the asynchronous operation, resulting in a <see cref="JsonWebToken"/>.
    /// This token is specifically formatted to conform to the OpenID Connect back-channel logout specification,
    /// containing claims such as 'sub', 'sid', and 'events' to indicate the logout event to the client.</returns>
    Task<EncodedJsonWebToken> CreateLogoutTokenAsync(ClientInfo clientInfo, LogoutContext logoutContext);
}
