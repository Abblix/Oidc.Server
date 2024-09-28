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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Defines the available delivery modes for backchannel token delivery in Client-Initiated Backchannel Authentication
/// (CIBA). These modes specify how the authentication server communicates the result of the backchannel authentication
/// process to the client.
/// </summary>
public class BackchannelTokenDeliveryModes
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
