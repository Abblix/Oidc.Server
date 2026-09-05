// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Defines the available delivery modes for backchannel token delivery in Client-Initiated Backchannel Authentication
/// (CIBA). These modes specify how the authentication server communicates the result of the backchannel authentication
/// process to the client.
/// </summary>
public static class BackchannelTokenDeliveryModes
{
    /// <summary>
    /// The "poll" mode where the client periodically polls the authorization server to check if the user has been
    /// authenticated. This method is useful in cases where the client prefers to control the polling interval and
    /// the process.
    /// </summary>
    public const string Poll = "poll";

    /// <summary>
    /// The "ping" mode where the authorization server notifies the client via a callback when the user has been
    /// authenticated. The client still needs to make a subsequent request to retrieve the token.
    /// </summary>
    public const string Ping = "ping";

    /// <summary>
    /// The "push" mode where the authorization server directly pushes the token to the client once the user has been
    /// authenticated. This method streamlines the process by delivering the token to the client without the need for
    /// further requests.
    /// </summary>
    public const string Push = "push";
}
