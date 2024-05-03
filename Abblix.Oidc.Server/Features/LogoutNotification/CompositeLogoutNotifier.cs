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

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Provides a mechanism to aggregate and execute multiple logout notification strategies for an OpenID Connect or OAuth 2.0 system.
/// </summary>
/// <remarks>
/// This class allows the system to support various logout mechanisms simultaneously, such as front-channel and back-channel logout,
/// by combining multiple <see cref="ILogoutNotifier"/> implementations. It ensures that all configured logout notifiers are invoked
/// to notify clients about the logout event, catering to different client capabilities and configurations.
/// </remarks>
public class CompositeLogoutNotifier: ILogoutNotifier
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CompositeLogoutNotifier"/> class.
    /// </summary>
    /// <param name="logoutNotifiers">An array of <see cref="ILogoutNotifier"/> implementations for handling logout notifications.</param>
    public CompositeLogoutNotifier(ILogoutNotifier[] logoutNotifiers)
    {
        _logoutNotifiers = logoutNotifiers;
    }

    private readonly ILogoutNotifier[] _logoutNotifiers;

    /// <summary>
    /// Asynchronously notifies all configured clients about a logout event by invoking each registered logout notifier.
    /// </summary>
    /// <param name="clientInfo">The information about the client that is being notified of the logout event.</param>
    /// <param name="logoutContext">Contextual information related to the logout event, including the user and session identifiers.</param>
    /// <returns>A task that represents the asynchronous operation of notifying all clients.</returns>
    /// <remarks>
    /// This method ensures that each logout notifier is called, regardless of the individual notifier's outcome.
    /// It allows for a unified approach to logout notifications, accommodating various client requirements and logout mechanisms.
    /// </remarks>
    public Task NotifyClientAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        var tasks = Array.ConvertAll(
            _logoutNotifiers,
            notifier => notifier.NotifyClientAsync(clientInfo, logoutContext));

        return Task.WhenAll(tasks);
    }

    public bool FrontChannelLogoutSupported => _logoutNotifiers.Any(notifier => notifier.FrontChannelLogoutSupported);

    public bool FrontChannelLogoutSessionSupported => _logoutNotifiers.Any(notifier => notifier.FrontChannelLogoutSessionSupported);

    public bool BackChannelLogoutSupported => _logoutNotifiers.Any(notifier => notifier.BackChannelLogoutSupported);

    public bool BackChannelLogoutSessionSupported => _logoutNotifiers.Any(notifier => notifier.BackChannelLogoutSessionSupported);
}
