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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Provides HTTP-based notification services for CIBA ping and push modes.
/// </summary>
/// <remarks>
/// <para>
/// This interface supports both CIBA notification modes by sending HTTP POST requests
/// with a notification payload to the client's registered endpoint.
/// </para>
/// <list type="bullet">
///   <item>
///     <strong>Ping Mode</strong>: Sends auth_req_id to notify client that tokens are ready for retrieval.
///   </item>
///   <item>
///     <strong>Push Mode</strong>: Delivers complete token response directly to client endpoint.
///   </item>
/// </list>
/// </remarks>
public interface INotificationDeliveryService
{
    /// <summary>
    /// Sends an HTTP POST notification to the client's registered endpoint.
    /// </summary>
    /// <param name="clientNotificationEndpoint">
    /// The HTTPS URL of the client's notification endpoint.
    /// </param>
    /// <param name="clientNotificationToken">
    /// Bearer token for authenticating the notification request.
    /// </param>
    /// <param name="payload">
    /// The notification payload to send (e.g., ping notification or push token delivery).
    /// </param>
    /// <param name="mode">
    /// The CIBA mode (e.g., "ping" or "push") for logging purposes.
    /// </param>
    /// <returns>A task representing the asynchronous notification operation.</returns>
    Task SendAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        IBackChannelNotificationRequest payload,
        string mode);
}
