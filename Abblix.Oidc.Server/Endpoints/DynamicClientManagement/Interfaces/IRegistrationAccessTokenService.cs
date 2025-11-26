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

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Provides functionality to issue registration access tokens for managing registered clients.
/// Per RFC 7592 Section 3, the registration access token is used to authenticate subsequent
/// operations on the client configuration endpoint.
/// </summary>
public interface IRegistrationAccessTokenService
{
    /// <summary>
    /// Issues a registration access token for a registered client.
    /// </summary>
    /// <param name="clientId">The unique identifier of the registered client.</param>
    /// <param name="issuedAt">The timestamp when the token is issued.</param>
    /// <param name="expiresIn">The optional duration after which the token expires.</param>
    /// <returns>A task that results in the encoded registration access token.</returns>
    /// <remarks>
    /// The registration access token is a bearer token that authenticates the client when
    /// performing read, update, or delete operations on its configuration.
    /// </remarks>
    Task<string> IssueTokenAsync(string clientId, DateTimeOffset issuedAt, TimeSpan? expiresIn);
}
