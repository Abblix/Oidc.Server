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
/// Implements the mechanism for notifying clients of logout events through the front-channel,
/// typically by redirecting the user's browser to a client-specific logout URL.
/// </summary>
public class FrontChannelLogoutNotifier: ILogoutNotifier
{
    /// <summary>
    /// Asynchronously notifies a client about a logout event by constructing and storing
    /// the front-channel logout URI, which can be used to redirect the user's browser
    /// to perform the logout process on the client's side.
    /// </summary>
    /// <param name="clientInfo">Information about the client that needs to be notified of the logout event.</param>
    /// <param name="logoutContext">Contextual information about the logout event, including the session ID and issuer.</param>
    /// <returns>A task that represents the asynchronous notification operation.</returns>
    /// <remarks>
    /// This method constructs a logout URI based on the client's configuration for front-channel logout,
    /// including necessary parameters such as issuer and session ID if by the client.
    /// It then adds the constructed URI to a collection for later use, typically for redirection.
    /// </remarks>
    public Task NotifyClientAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        NotifyClient(clientInfo, logoutContext);
        return Task.CompletedTask;
    }

    public bool FrontChannelLogoutSupported => true;

    public bool FrontChannelLogoutSessionSupported => true;

    public bool BackChannelLogoutSupported => false;

    public bool BackChannelLogoutSessionSupported => false;

    private static void NotifyClient(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        if (clientInfo is not { FrontChannelLogout: { Uri: var uri, RequiresSessionId: var requiresSid } })
            return;

        if (requiresSid)
        {
            if (string.IsNullOrEmpty(logoutContext.SessionId))
            {
                throw new InvalidOperationException($"The client {clientInfo.ClientId} requires session id");
            }

            uri = new UriBuilder(uri)
            {
                Query =
                {
                    [Parameters.Issuer] = logoutContext.Issuer,
                    [Parameters.SessionId] = logoutContext.SessionId,
                }
            };
        }

        // Store the logout URI for later redirection
        logoutContext.FrontChannelLogoutRequestUris.Add(uri);
    }

    /// <summary>
    /// Contains constants for the query parameter names used in constructing front-channel logout URIs.
    /// </summary>
    private static class Parameters
    {
        public const string Issuer = "iss";
        public const string SessionId = "sid";
    }
}
