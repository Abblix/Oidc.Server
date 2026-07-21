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
/// The parts of a Logout Token that are particular to it, named as on the wire.
/// </summary>
/// <remarks>
/// Its ordinary claims (<c>iss</c>, <c>aud</c>, <c>iat</c>, <c>exp</c>, <c>jti</c>, <c>sub</c>, <c>sid</c>)
/// are the registered ones and are named by <c>Abblix.Jwt</c>. What is named here is what only this
/// specification defines.
/// </remarks>
public static class LogoutTokenClaims
{
    /// <summary>
    /// The member of the <c>events</c> claim that marks a token as a back-channel logout notification.
    /// </summary>
    /// <remarks>
    /// OpenID Connect Back-Channel Logout 1.0 section 2.4 requires an <c>events</c> claim "whose value is a
    /// JSON object containing the member name http://schemas.openid.net/event/backchannel-logout". The
    /// member value carries nothing; its presence is the statement.
    /// </remarks>
    public const string BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    /// <summary>
    /// The <c>typ</c> header value that says a JWT is a Logout Token.
    /// </summary>
    /// <remarks>
    /// Section 4.1 offers it against cross-JWT confusion, and says in the same breath why it cannot be
    /// demanded: "requiring explicitly typed Logout Tokens will break most existing deployments". So this
    /// client accepts a token that carries it and does not refuse one that does not.
    /// </remarks>
    public const string LogoutTokenType = "logout+jwt";
}
