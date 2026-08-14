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

using System.Diagnostics.CodeAnalysis;

namespace Abblix.SharedSignals.Receiver.BackChannelLogout;

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
