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
