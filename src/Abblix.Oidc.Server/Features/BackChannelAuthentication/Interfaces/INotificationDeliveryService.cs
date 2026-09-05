// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// <returns>
    /// <c>true</c> if the client endpoint accepted the notification (2xx response); <c>false</c> if
    /// delivery failed (non-success status or transport error).
    /// <para>
    /// On <c>false</c> push keeps the stored record, and it is not a resumable delivery. The tokens were
    /// minted and are gone; nothing retries them. The record reads Authenticated, written before the
    /// mint, so a LATER completion of the same request is refused - the recovery is to ask the end user,
    /// not to resend from what is left.
    /// </para>
    /// </returns>
    Task<bool> SendAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        IBackChannelNotificationRequest payload,
        string mode);
}
