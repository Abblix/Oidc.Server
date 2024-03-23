// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
