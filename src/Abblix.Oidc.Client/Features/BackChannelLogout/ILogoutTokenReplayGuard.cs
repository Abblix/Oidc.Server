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

namespace Abblix.Oidc.Client.Features.BackChannelLogout;

/// <summary>
/// Remembers the Logout Tokens this client has already acted on, so one cannot be acted on twice.
/// </summary>
/// <remarks>
/// Step 8 of OpenID Connect Back-Channel Logout 1.0 section 2.6: "Optionally verify that another Logout
/// Token with the same jti value has not been recently received."
/// It is worth doing because the request carrying the token is unauthenticated and the token is a bearer
/// credential in the plainest sense: anyone who observes one - a proxy, a log, a browser extension on the
/// wrong machine - can post it again. Section 4 asks providers to keep the window short, "preferably at most
/// two minutes in the future, to prevent captured Logout Tokens from being replayable", and this is the
/// other half of that: within those two minutes, nothing but a record of what has been seen can tell a
/// replay from the original.
/// </remarks>
public interface ILogoutTokenReplayGuard
{
    /// <summary>
    /// Records a Logout Token as seen, and says whether it had been seen already.
    /// </summary>
    /// <param name="tokenId">The <c>jti</c> of the token.</param>
    /// <param name="expiresAt">
    /// When the token stops being usable. Nothing needs to be remembered past that: an expired token is
    /// refused by the checks before this one, so it can no longer be replayed whether it is remembered
    /// or not.
    /// </param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <returns>
    /// <c>true</c> when this token had not been seen and is now recorded; <c>false</c> when it had.
    /// </returns>
    /// <remarks>
    /// Recording and checking are one operation on purpose. Two concurrent posts of the same token would
    /// otherwise both find nothing recorded, both record, and both proceed - which is the case the guard
    /// exists for.
    /// </remarks>
    Task<bool> TryRecordAsync(
        string tokenId, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}
