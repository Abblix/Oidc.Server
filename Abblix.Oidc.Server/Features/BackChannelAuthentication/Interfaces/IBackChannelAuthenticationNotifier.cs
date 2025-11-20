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
/// Provides notification services for CIBA authentication completion, automatically selecting
/// and delegating to the appropriate delivery mode implementation (poll, ping, or push) based
/// on the client's configured backchannel_token_delivery_mode.
/// </summary>
public interface IBackChannelAuthenticationNotifier
{
    /// <summary>
    /// Notifies that user authentication has completed and handles token delivery according to
    /// the client's configured delivery mode.
    /// </summary>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <param name="request">The authentication request with Authenticated status and authorized grant.</param>
    /// <param name="expiresIn">How long the authenticated request remains valid for token retrieval.</param>
    /// <returns>A task representing the asynchronous notification operation.</returns>
    /// <remarks>
    /// This method automatically:
    /// <list type="bullet">
    ///   <item>Retrieves client information to determine the delivery mode</item>
    ///   <item>Selects the appropriate notifier (PollModeNotifier, PingModeNotifier, or PushModeNotifier)</item>
    ///   <item>Delegates to the mode-specific implementation for token delivery</item>
    /// </list>
    /// </remarks>
    Task NotifyAuthenticationCompleteAsync(
        string authenticationRequestId,
        BackChannelAuthenticationRequest request,
        TimeSpan expiresIn);
}
