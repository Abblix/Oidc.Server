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

namespace Abblix.SharedSignals.Receiver.BackChannelLogout;

/// <summary>
/// Where validated logout orders land: the application's half of the receiver, called once per
/// accepted Logout Token with the notification already carrying its provider's authority.
/// </summary>
/// <remarks>
/// <para>
/// This is the work OpenID Connect Back-Channel Logout 1.0 Section 2.7 gives the RP: "locate the
/// session(s) identified by the iss and sub Claims and/or the sid Claim", then "clear any state
/// associated with the identified session(s)". Only the application knows where it keeps them,
/// which is why the library validates and stops here.
/// </para>
/// <para>
/// Processing must be idempotent. The replay guard in front of this sink refuses a token it has
/// already recorded, but a provider may legitimately end the same session twice - a second logout
/// after a re-login - and Section 2.5 permits a retransmission when the provider suspects the
/// first failed.
/// </para>
/// <para>
/// The verdict is the sink's to give: null answers the provider with success, a description
/// travels back in the 400 response. Section 2.8 makes both outcomes the RP's own statement -
/// "if the logout request was invalid or the logout FAILED" - so a sink that could not end the
/// sessions says so rather than acknowledging work it did not do.
/// </para>
/// </remarks>
public interface ILogoutNotificationSink
{
    /// <summary>
    /// Acts on one validated logout order.
    /// </summary>
    /// <param name="notification">Which sessions the provider says to end.</param>
    /// <param name="cancellationToken">Cancels the processing.</param>
    /// <returns>
    /// Null to answer success, or a human-readable account of why the logout failed.</returns>
    Task<string?> ConsumeAsync(
        LogoutNotification notification,
        CancellationToken cancellationToken = default);
}
