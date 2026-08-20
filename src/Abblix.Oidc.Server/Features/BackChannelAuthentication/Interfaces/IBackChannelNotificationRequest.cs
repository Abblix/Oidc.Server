// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;

/// <summary>
/// Common shape of the JSON body the authorization server posts to the client's
/// <c>client_notification_endpoint</c> in CIBA ping and push modes. The
/// <c>auth_req_id</c> is always present; push payloads add the issued tokens.
/// </summary>
public interface IBackChannelNotificationRequest
{
    /// <summary>
    /// The <c>auth_req_id</c> the notification refers to, allowing the client to correlate
    /// the callback with the originating CIBA authentication request.
    /// </summary>
    string AuthenticationRequestId { get; init; }
}
