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

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

/// <summary>
/// Defines the possible states of a JSON Web Token within the system.
/// </summary>
public enum JsonWebTokenStatus
{
    /// <summary>
    /// Indicates that the status of the token is not known.
    /// This may be used as a default value when the token's status has not been explicitly set or determined.
    /// </summary>
    Unknown,

    /// <summary>
    /// Indicates that the token has been used.
    /// This status can be used to mark tokens that have been consumed in a process, such as authorization codes that have been exchanged for access tokens.
    /// </summary>
    Used,

    /// <summary>
    /// Indicates that the token has been revoked.
    /// A revoked token is no longer valid for use and should be rejected in any validation checks.
    /// This status is typically set when a user or system administrator manually invalidates a token.
    /// </summary>
    Revoked,
}
