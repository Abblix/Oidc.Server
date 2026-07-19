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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Provides definitions for standard OpenID Connect scopes and their associated claims.
/// </summary>
public static class StandardScopes
{
    /// <summary>
    /// Represents the 'openid' scope, which is essential for OpenID Connect processes.
    /// </summary>
    public static readonly ScopeDefinition OpenId = new(
        Scopes.OpenId,
        IanaClaimTypes.Sub);

    /// <summary>
    /// Represents the 'profile' scope, including claims about the end-user's profile information.
    /// </summary>
    public static readonly ScopeDefinition Profile = new(
        Scopes.Profile,
        IanaClaimTypes.Name,
        IanaClaimTypes.FamilyName,
        IanaClaimTypes.GivenName,
        IanaClaimTypes.MiddleName,
        IanaClaimTypes.Nickname,
        IanaClaimTypes.PreferredUsername,
        IanaClaimTypes.Profile,
        IanaClaimTypes.Picture,
        IanaClaimTypes.Website,
        IanaClaimTypes.Gender,
        IanaClaimTypes.Birthdate,
        IanaClaimTypes.Zoneinfo,
        IanaClaimTypes.Locale,
        IanaClaimTypes.UpdatedAt);

    /// <summary>
    /// Represents the 'address' scope, including claims about the end-user's physical address.
    /// </summary>
    public static readonly ScopeDefinition Address = new(
        Scopes.Address,
        IanaClaimTypes.Address);

    /// <summary>
    /// Represents the 'email' scope, including claims about the end-user's email address and verification status.
    /// </summary>
    public static readonly ScopeDefinition Email = new(
        Scopes.Email,
        IanaClaimTypes.Email,
        IanaClaimTypes.EmailVerified);

    /// <summary>
    /// Represents the 'phone' scope, including claims about the end-user's phone number and verification status.
    /// </summary>
    public static readonly ScopeDefinition Phone = new(
        Scopes.Phone,
        IanaClaimTypes.PhoneNumber,
        IanaClaimTypes.PhoneNumberVerified);

    /// <summary>
    /// Represents the 'offline_access' scope, which allows the client to request refresh tokens for long-term access.
    /// </summary>
    public static readonly ScopeDefinition OfflineAccess = new(
        Scopes.OfflineAccess);
}
