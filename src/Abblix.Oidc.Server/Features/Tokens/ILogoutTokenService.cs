// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.LogoutNotification;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Issues OpenID Connect Back-Channel Logout tokens (OIDC Back-Channel Logout 1.0 section 2.4): JWTs
/// with an <c>events</c> claim containing the back-channel logout event URI, addressed to a
/// specific RP and identifying the affected end-user via <c>sub</c> and/or <c>sid</c>. The
/// <c>nonce</c> claim is prohibited per the specification.
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
