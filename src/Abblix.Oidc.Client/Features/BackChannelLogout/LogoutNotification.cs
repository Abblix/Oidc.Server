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
/// Which sessions a validated Logout Token says to end.
/// </summary>
/// <remarks>
/// What OpenID Connect Back-Channel Logout 1.0 section 2.7 asks the RP to act on: "locate the session(s)
/// identified by the iss and sub Claims and/or the sid Claim", then "clear any state associated with the
/// identified session(s)". Acting is the host's, since only the host knows where its sessions are kept.
/// </remarks>
/// <param name="Issuer">The provider that sent the notification.</param>
/// <param name="Subject">
/// The end-user whose sessions are ending, when the token named one. Every session this client holds for
/// that user at that issuer is meant, not one of them.
/// </param>
/// <param name="SessionId">
/// The single session that is ending, when the token named one. Narrower than the subject, and the two may
/// arrive together.
/// </param>
/// <param name="TokenId">The <c>jti</c> of the token that carried this notification.</param>
public sealed record LogoutNotification(
    string Issuer,
    string? Subject,
    string? SessionId,
    string? TokenId);
