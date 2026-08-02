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

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// The security event identifiers this server emits for logout notification. An event identifier
/// is a wire name every receiver keys on, so it lives as a constant rather than a literal beside
/// its first use.
/// </summary>
public static class LogoutTokenEvents
{
    /// <summary>
    /// The Back-Channel Logout event statement's identifier, fixed by OpenID Connect Back-Channel
    /// Logout 1.0 Section 2.4: the member under the "events" claim whose presence is what makes a
    /// token a logout order. Its value is always the empty JSON object, as the specification
    /// requires.
    /// </summary>
    public const string BackChannelLogout = "http://schemas.openid.net/event/backchannel-logout";
}
