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
    /// <returns>A task that returns a <see cref="JsonWebToken"/>.
    /// This token is specifically formatted to conform to the OpenID Connect back-channel logout specification,
    /// containing claims such as 'sub', 'sid', and 'events' to indicate the logout event to the client.</returns>
    Task<EncodedJsonWebToken> CreateLogoutTokenAsync(ClientInfo clientInfo, LogoutContext logoutContext);
}
