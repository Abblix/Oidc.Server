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
/// Implements the mechanism for notifying clients about logout events through the back-channel,
/// leveraging logout tokens to securely communicate the logout state to client applications.
/// </summary>
public class BackChannelLogoutNotifier : ILogoutNotifier
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BackChannelLogoutNotifier"/> class, setting up
    /// the services for logout token creation and distribution.
    /// </summary>
    /// <param name="logoutTokenService">The service responsible for creating logout tokens that encapsulate
    /// the details of the logout event.</param>
    /// <param name="logoutTokenSender">The service responsible for sending the logout tokens to the client
    /// applications via back-channel communication.</param>
    public BackChannelLogoutNotifier(
        ILogoutTokenService logoutTokenService,
        ILogoutTokenSender logoutTokenSender)
    {
        _logoutTokenService = logoutTokenService;
        _logoutTokenSender = logoutTokenSender;
    }

    private readonly ILogoutTokenService _logoutTokenService;
    private readonly ILogoutTokenSender _logoutTokenSender;

    /// <summary>
    /// Asynchronously notifies a client of a logout event by creating a logout token and sending it to the client's
    /// back-channel logout endpoint. This ensures that the client application is informed about the logout event
    /// and can take appropriate actions, such as invalidating the user's session.
    /// </summary>
    /// <param name="clientInfo">The client information, including the back-channel logout URI, to which the logout
    /// notification should be sent.</param>
    /// <param name="logoutContext">The context of the logout event, containing details such as the subject identifier
    /// and session identifier, which are included in the logout token.</param>
    /// <returns>A task that represents the asynchronous operation of notifying the client. The task completes when
    /// the notification has been successfully sent to the client's back-channel logout endpoint.</returns>
    public async Task NotifyClientAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        // Ensure the client supports back-channel logout
        if (clientInfo.BackChannelLogout == null)
            return;

        // Create the logout token specific to the logout event and client
        var logoutToken = await _logoutTokenService.CreateLogoutTokenAsync(clientInfo, logoutContext);

        // Send the logout token to the client's back-channel logout endpoint
        await _logoutTokenSender.SendBackChannelLogoutAsync(clientInfo, logoutToken);
    }

    public bool FrontChannelLogoutSupported => false;

    public bool FrontChannelLogoutSessionSupported => false;

    public bool BackChannelLogoutSupported => true;

    public bool BackChannelLogoutSessionSupported => true;
}
