// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;

/// <summary>
/// Checks whether an initial access token has been revoked.
/// Implementations may use a database, distributed cache, or other store.
/// </summary>
public interface IInitialAccessTokenRevocationProvider
{
    /// <summary>
    /// Determines whether the initial access token with the specified identifier has been revoked.
    /// </summary>
    /// <param name="subject">The unique identifier of the token (from the JWT subject claim).</param>
    /// <returns>
    /// A task that results in <c>true</c> if the token has been revoked, <c>false</c> otherwise.
    /// </returns>
    Task<bool> IsRevokedAsync(string subject);
}
