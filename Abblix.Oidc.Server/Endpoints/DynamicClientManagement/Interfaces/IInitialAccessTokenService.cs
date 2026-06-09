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
/// Issues initial access tokens that authorize calls to the client registration endpoint
/// per RFC 7591 Section 3.
/// </summary>
public interface IInitialAccessTokenService
{
    /// <summary>
    /// Issues an initial access token for authorizing client registration.
    /// </summary>
    /// <param name="subject">A unique identifier for the token, used as the JWT subject for revocation tracking.</param>
    /// <param name="issuedAt">The timestamp when the token is issued.</param>
    /// <param name="expiresIn">The optional duration after which the token expires.</param>
    /// <returns>A task that results in the encoded initial access token.</returns>
    Task<string> IssueTokenAsync(string subject, DateTimeOffset issuedAt, TimeSpan? expiresIn);
}
