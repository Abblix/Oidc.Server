// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Decides which clients' ID tokens and logout messages carry the end user's session identifier, so the two name the
/// session for the same clients.
/// </summary>
/// <remarks>
/// OpenID Connect Front-Channel Logout 1.0 section 3 and Back-Channel Logout 1.0 section 2.1 define the <c>sid</c>
/// claim of an ID token for one use, matching a logout message to the session it ends. A client that receives no
/// such message has nothing to match it against, so its ID token goes out without the claim, which the profiles
/// that check ID tokens for claims they do not expect would otherwise flag.
/// <para>
/// The discovery metadata <c>frontchannel_logout_session_supported</c> and
/// <c>backchannel_logout_session_supported</c> are each defined with the sentence "If supported, the sid Claim is
/// also included in ID Tokens issued by the OP." It carries no requirement keyword, and the claim it names is
/// OPTIONAL, so this server reads it as describing the ID tokens of the clients that use the session at logout:
/// the server announces that it can pass the session, and states it to the clients that receive it.
/// </para>
/// </remarks>
internal static class SessionIdDisclosure
{
    /// <summary>
    /// Whether the client's front-channel logout URI carries <c>iss</c> and <c>sid</c>: it registered
    /// <c>frontchannel_logout_session_required</c>.
    /// </summary>
    public static bool InFrontChannelLogout(ClientInfo clientInfo)
        => clientInfo.FrontChannelLogout is { RequiresSessionId: true };

    /// <summary>
    /// Whether the ID token issued to the client carries <c>sid</c>: exactly when one of its logout messages does.
    /// </summary>
    /// <remarks>
    /// Every logout token this server issues names the session it ends, whether or not the client registered
    /// <c>backchannel_logout_session_required</c>, and Back-Channel Logout 1.0 section 2.6 lets the client verify
    /// that <c>sid</c> against the one in its ID token, so any back-channel logout URI is enough.
    /// </remarks>
    public static bool InIdentityToken(ClientInfo clientInfo)
        => InFrontChannelLogout(clientInfo) || clientInfo.BackChannelLogout is not null;
}
