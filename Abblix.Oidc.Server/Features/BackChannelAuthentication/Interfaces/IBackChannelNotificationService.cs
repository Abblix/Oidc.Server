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

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Provides notification services for CIBA ping mode, enabling the authorization server to notify
/// clients when user authentication is complete.
/// </summary>
/// <remarks>
/// In CIBA ping mode, the authorization server sends an HTTP POST notification to the client's
/// registered notification endpoint when the user completes authentication, allowing the client
/// to retrieve tokens without continuous polling.
/// </remarks>
public interface IBackChannelNotificationService
{
    /// <summary>
    /// Sends a notification to the client's registered endpoint informing them that the user
    /// has completed authentication and tokens are ready for retrieval.
    /// </summary>
    /// <param name="clientNotificationEndpoint">The client's registered notification endpoint URL.</param>
    /// <param name="clientNotificationToken">Bearer token for authenticating the notification request.</param>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <returns>A task representing the asynchronous notification operation.</returns>
    Task NotifyAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        string authenticationRequestId);
}
