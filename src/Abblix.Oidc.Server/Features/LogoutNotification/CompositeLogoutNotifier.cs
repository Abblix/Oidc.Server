// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Provides a mechanism to aggregate and execute multiple logout notification strategies for an OpenID Connect or OAuth 2.0 system.
/// </summary>
/// <param name="logoutNotifiers">An array of <see cref="ILogoutNotifier"/> implementations for handling logout notifications.</param>
/// <remarks>
/// This class allows the system to support various logout mechanisms simultaneously, such as front-channel and back-channel logout,
/// by combining multiple <see cref="ILogoutNotifier"/> implementations. It ensures that all configured logout notifiers are invoked
/// to notify clients about the logout event, catering to different client capabilities and configurations.
/// </remarks>
public class CompositeLogoutNotifier(ILogoutNotifier[] logoutNotifiers) : ILogoutNotifier
{
    /// <summary>
    /// Asynchronously notifies all configured clients about a logout event by invoking each registered logout notifier.
    /// </summary>
    /// <param name="clientInfo">The information about the client that is being notified of the logout event.</param>
    /// <param name="logoutContext">Contextual information related to the logout event, including the user and session identifiers.</param>
    /// <returns>A task that completes when all clients are notified.</returns>
    /// <remarks>
    /// This method ensures that each logout notifier is called, regardless of the individual notifier's outcome.
    /// It allows for a unified approach to logout notifications, accommodating various client requirements and logout mechanisms.
    /// </remarks>
    public Task NotifyClientAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        var tasks = Array.ConvertAll(
            logoutNotifiers,
            notifier => notifier.NotifyClientAsync(clientInfo, logoutContext));

        return Task.WhenAll(tasks);
    }

    /// <inheritdoc />
    public bool FrontChannelLogoutSupported => logoutNotifiers.Any(notifier => notifier.FrontChannelLogoutSupported);

    /// <inheritdoc />
    public bool FrontChannelLogoutSessionSupported => logoutNotifiers.Any(notifier => notifier.FrontChannelLogoutSessionSupported);

    /// <inheritdoc />
    public bool BackChannelLogoutSupported => logoutNotifiers.Any(notifier => notifier.BackChannelLogoutSupported);

    /// <inheritdoc />
    public bool BackChannelLogoutSessionSupported => logoutNotifiers.Any(notifier => notifier.BackChannelLogoutSessionSupported);
}
