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
