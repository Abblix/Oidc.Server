// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// <param name="tokenId">
    /// The identifier (jti) to embed in the token. The caller records this value via the
    /// registration-access-token store so the validator can bind the token to the client: issuing
    /// with a fresh id invalidates earlier tokens, reusing the stored id keeps them valid
    /// (idempotent read).
    /// </param>
    /// <returns>A task that results in the encoded registration access token.</returns>
    /// <remarks>
    /// The registration access token is a bearer token that authenticates the client when
    /// performing read, update, or delete operations on its configuration.
    /// </remarks>
    Task<string> IssueTokenAsync(string clientId, DateTimeOffset issuedAt, TimeSpan? expiresIn, string tokenId);
}
