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

namespace Abblix.Jwt;

/// <summary>
/// Defines constants used with JwtSecurityTokenHandler, particularly for specifying claim types
/// that should be excluded during certain operations.
/// </summary>
internal static class JwtSecurityTokenHandlerConstants
{
    /// <summary>
    /// An array of claim types that are often excluded from JWT token processing.
    /// These claims are typically handled specially by JWT security token handlers
    /// due to their significance in the JWT standard and security implications.
    /// </summary>
    public static readonly string[] ClaimTypesToExclude = {

        // Issuer claim, identifies the principal that issued the JWT.
        IanaClaimTypes.Iss,

        // Audience claim, identifies the recipients that the JWT is intended for.
        IanaClaimTypes.Aud,

        // Expiration time claim, specifies the expiration time on or after which the JWT must not be accepted.
        IanaClaimTypes.Exp,

        // Not before claim, specifies the time before which the JWT must not be accepted.
        IanaClaimTypes.Nbf,

        // Issued at claim, indicates the time at which the JWT was issued.
        IanaClaimTypes.Iat,
    };
}
