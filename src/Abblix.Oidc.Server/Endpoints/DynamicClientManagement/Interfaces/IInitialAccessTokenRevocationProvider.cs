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
