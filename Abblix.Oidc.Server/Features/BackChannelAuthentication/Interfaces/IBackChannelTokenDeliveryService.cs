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
/// Provides token delivery services for CIBA push mode, enabling the authorization server to directly
/// deliver tokens to the client's registered notification endpoint.
/// </summary>
/// <remarks>
/// In CIBA push mode, the authorization server sends the complete token response (access_token, id_token,
/// refresh_token) directly to the client's notification endpoint when authentication completes, eliminating
/// the need for the client to poll the token endpoint. The ID token includes special claims (at_hash,
/// urn:openid:params:jwt:claim:auth_req_id) for validation.
/// </remarks>
public interface IBackChannelTokenDeliveryService
{
    /// <summary>
    /// Delivers tokens directly to the client's registered notification endpoint in CIBA push mode.
    /// </summary>
    /// <param name="clientNotificationEndpoint">The client's registered notification endpoint URL.</param>
    /// <param name="clientNotificationToken">Bearer token for authenticating the push request to the client.</param>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <param name="tokenResponse">The complete token response containing access_token, id_token, and optional refresh_token.</param>
    /// <returns>A task representing the asynchronous token delivery operation.</returns>
    /// <remarks>
    /// The token response must include an ID token with at_hash and urn:openid:params:jwt:claim:auth_req_id claims
    /// per the CIBA specification for push mode.
    /// </remarks>
    Task DeliverTokensAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        string authenticationRequestId,
        TokenIssued tokenResponse);
}
