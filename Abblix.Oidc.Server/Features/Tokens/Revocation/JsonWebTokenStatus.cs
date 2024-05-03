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
