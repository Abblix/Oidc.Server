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

using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Defines the interface for a service responsible for sending logout tokens to clients via the back-channel.
/// </summary>
public interface ILogoutTokenSender
{
    /// <summary>
    /// Asynchronously sends a logout token to a client using back-channel communication.
    /// </summary>
    /// <param name="clientInfo">The information about the client to which the logout token will be sent.
    ///     This includes the client's identifier and any relevant endpoints for back-channel communication.</param>
    /// <param name="logoutToken">The logout token that encapsulates the logout information.
    ///     This token is typically a JSON Web Token (JWT) that contains claims relevant to the logout event,
    ///     such as the subject identifier and the session identifier.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation of sending the logout token.
    /// The task completes when the logout token has been successfully sent to the client's back-channel endpoint,
    /// or an attempt has been made to send the token.</returns>
    /// <remarks>
    /// Implementations of this interface are responsible for securely transmitting the logout token
    /// to the client's back-channel endpoint specified in the <paramref name="clientInfo"/>. This process
    /// usually involves making an HTTP POST request to the client's back-channel logout URI with the logout token
    /// included in the request body.
    /// 
    /// It's important for implementations to handle any errors or exceptions that may occur during
    /// the transmission process and ensure proper logging and error handling mechanisms are in place.
    /// This ensures that logout events are reliably communicated to clients, even in scenarios where
    /// direct user-agent-based communication (front-channel logout) is not feasible.
    /// </remarks>
    Task SendBackChannelLogoutAsync(ClientInfo clientInfo, EncodedJsonWebToken logoutToken);
}
