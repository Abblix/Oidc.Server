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

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Defines a contract for generating entity storage keys with consistent formatting.
/// Provides standardized key generation for all OIDC storage entities.
/// </summary>
public interface IEntityStorageKeyFactory
{
    /// <summary>
    /// Generates a storage key for JWT status by JWT ID.
    /// </summary>
    /// <param name="jwtId">The JSON Web Token identifier.</param>
    /// <returns>A formatted storage key for the JWT status.</returns>
    string JsonWebTokenStatusKey(string jwtId);

    /// <summary>
    /// Generates a storage key for an authorization request by URI.
    /// </summary>
    /// <param name="requestUri">The pushed authorization request URI.</param>
    /// <returns>A formatted storage key for the authorization request.</returns>
    string AuthorizationRequestKey(Uri requestUri);

    /// <summary>
    /// Generates a storage key for an authorized grant by authorization code.
    /// </summary>
    /// <param name="authorizationCode">The OAuth 2.0 authorization code.</param>
    /// <returns>A formatted storage key for the authorization grant.</returns>
    string AuthorizedGrantKey(string authorizationCode);

    /// <summary>
    /// Generates a storage key for a backchannel authentication request by request ID.
    /// </summary>
    /// <param name="requestId">The CIBA authentication request identifier.</param>
    /// <returns>A formatted storage key for the backchannel authentication request.</returns>
    string BackChannelAuthenticationRequestKey(string requestId);
}
