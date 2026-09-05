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
/// Defines an interface for a service responsible for notifying clients about logout events.
/// This interface supports both front-channel and back-channel logout mechanisms, allowing
/// implementations to handle client notifications through direct user agent redirection or
/// server-to-server communication, respectively.
/// </summary>
public interface ILogoutNotifier
{
    /// <summary>
    /// Asynchronously notifies a client about a logout event, providing the client with
    /// information necessary to process the logout on its end.
    /// </summary>
    /// <param name="clientInfo">The information about the client that needs to be notified.
    /// This includes details such as the client ID and the logout endpoint URI.</param>
    /// <param name="logoutContext">The context of the logout event, including any relevant
    /// information such as the session ID and the subject ID of the user. This context
    /// is essential for clients to understand the scope and reason for the logout, enabling
    /// them to perform appropriate actions, such as clearing session data or redirecting the user.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation of notifying the client.
    /// The task completes when the notification has been successfully sent to the client or
    /// an attempt has been made to notify the client.</returns>
    /// <remarks>
    /// Implementations of this interface should handle any exceptions that occur during
    /// the notification process and ensure that all clients are notified as configured,
    /// regardless of the mechanism used (front-channel or back-channel).
    /// </remarks>
    Task NotifyClientAsync(ClientInfo clientInfo, LogoutContext logoutContext);

    /// <summary>
    /// Indicates whether the logout notifier supports front-channel logout,
    /// enabling clients to be notified of logout events via user-agent redirection.
    /// </summary>
    bool FrontChannelLogoutSupported { get; }

    /// <summary>
    /// Indicates whether the logout notifier supports front-channel logout session management,
    /// allowing for more precise control over session termination during a front-channel logout.
    /// </summary>
    bool FrontChannelLogoutSessionSupported { get; }

    /// <summary>
    /// Indicates whether the logout notifier supports back-channel logout,
    /// enabling server-to-server communication to notify clients of logout events.
    /// </summary>
    bool BackChannelLogoutSupported { get; }

    /// <summary>
    /// Indicates whether the logout notifier supports back-channel logout session management,
    /// facilitating the management of user sessions during a back-channel logout.
    /// </summary>
    bool BackChannelLogoutSessionSupported { get; }
}
