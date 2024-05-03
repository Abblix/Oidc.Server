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
