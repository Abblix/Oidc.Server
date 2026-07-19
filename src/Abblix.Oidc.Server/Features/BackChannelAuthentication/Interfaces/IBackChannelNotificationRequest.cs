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
