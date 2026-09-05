// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.BackChannelLogout;

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
