// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
