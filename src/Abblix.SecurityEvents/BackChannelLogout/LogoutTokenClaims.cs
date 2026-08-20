// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// The part of a Logout Token that only its own specification defines, named as on the wire.
/// </summary>
/// <remarks>
/// Its ordinary claims (<c>iss</c>, <c>aud</c>, <c>iat</c>, <c>exp</c>, <c>jti</c>, <c>sub</c>,
/// <c>sid</c>) are the registered ones and are named by <c>Abblix.Jwt</c>, and its type value by
/// <see cref="Abblix.Jwt.JsonWebTokenTypes.LogoutToken"/>.
/// </remarks>
public static class LogoutTokenClaims
{
    /// <summary>
    /// The member of the <c>events</c> claim that marks a token as a back-channel logout
    /// notification.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Back-Channel Logout 1.0 Section 2.4 requires an <c>events</c> claim "whose
    /// value is JSON object containing the member name
    /// http://schemas.openid.net/event/backchannel-logout". The member value carries nothing; its
    /// presence is the statement.
    /// </remarks>
    [SuppressMessage("Minor Vulnerability", "S5332:Using clear-text protocols is security-sensitive",
        Justification = "Not an address anything connects to: the exact string OpenID Connect Back-Channel "
            + "Logout 1.0 Section 2.4 defines as the events member name, matched literally against the "
            + "token. The https spelling is a different identifier, which no conformant token carries.")]
    public const string BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";
}
