// Abblix OIDC Client Library
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


namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// The error codes a token endpoint returns, named as on the wire (RFC 6749 section 5.2).
/// </summary>
public static class TokenErrorCodes
{
    /// <summary>
    /// The grant presented is no longer good: an authorization code already redeemed or expired, or a
    /// refresh token that has been rotated away.
    /// </summary>
    /// <remarks>
    /// The one code a client must react to rather than merely report. On a refresh it usually means another
    /// request for the same session already rotated the token, which is a race to recover from, not a reason
    /// to end the session.
    /// </remarks>
    public const string InvalidGrant = "invalid_grant";
}
