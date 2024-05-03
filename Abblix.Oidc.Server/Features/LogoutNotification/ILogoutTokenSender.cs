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
