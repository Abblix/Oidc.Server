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
