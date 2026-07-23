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
/// The error codes a token endpoint returns that this client must react to rather than merely report,
/// named as on the wire.
/// </summary>
/// <remarks>
/// The citation belongs on each member, not on the class: only <c>invalid_grant</c> comes from RFC 6749
/// section 5.2, and the four that follow it are defined by RFC 8628 section 3.5 for the device grant, which
/// CIBA section 11 then adopts in the same words. A single class-level reference read as though one document
/// defined them all.
/// </remarks>
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

    /// <summary>
    /// The device's user has not finished authorizing it yet, so the client polls again after the interval
    /// (RFC 8628 section 3.5).
    /// </summary>
    public const string AuthorizationPending = "authorization_pending";

    /// <summary>
    /// The same as <see cref="AuthorizationPending"/>, except that the provider is telling the client it is
    /// asking too often: RFC 8628 section 3.5 says the interval "MUST be increased by 5 seconds for this and
    /// all subsequent requests".
    /// </summary>
    public const string SlowDown = "slow_down";

    /// <summary>
    /// The device code has expired and its session is over. The client may start a new one, but RFC 8628
    /// section 3.5 says it should wait for the user before doing so rather than polling on.
    /// </summary>
    public const string ExpiredToken = "expired_token";

    /// <summary>
    /// The user refused the device (RFC 8628 section 3.5). Final: there is nothing to poll for.
    /// </summary>
    public const string AccessDenied = "access_denied";
}
