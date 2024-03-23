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
