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
/// Implements OpenID Connect Front-Channel Logout 1.0 notification by collecting per-client logout URIs
/// (with <c>iss</c> and <c>sid</c> appended when the client requires session identifiers) into the
/// <see cref="LogoutContext"/>. The end-session endpoint later renders these URIs as iframes so each
/// client receives the logout signal through the user agent.
/// </summary>
public class FrontChannelLogoutNotifier: ILogoutNotifier
{
    /// <summary>
    /// Builds the client's front-channel logout URI (appending <c>iss</c> and <c>sid</c> when the
    /// client's <c>frontchannel_logout_session_required</c> is set) and adds it to
    /// <see cref="LogoutContext.FrontChannelLogoutRequestUris"/> for later iframe rendering.
    /// Throws <see cref="InvalidOperationException"/> if the client requires <c>sid</c> but the
    /// context has no session identifier.
    /// </summary>
    /// <param name="clientInfo">Information about the client that needs to be notified of the logout event.</param>
    /// <param name="logoutContext">Contextual information about the logout event, including the session ID and issuer.</param>
    public Task NotifyClientAsync(ClientInfo clientInfo, LogoutContext logoutContext)
    {
        NotifyClient(clientInfo, logoutContext);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public bool FrontChannelLogoutSupported => true;

    /// <inheritdoc />
    public bool FrontChannelLogoutSessionSupported => true;

    /// <inheritdoc />
    public bool BackChannelLogoutSupported => false;

    /// <inheritdoc />
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
