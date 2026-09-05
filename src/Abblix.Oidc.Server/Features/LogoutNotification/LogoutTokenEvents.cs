// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;

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
    [SuppressMessage("Minor Vulnerability", "S5332:Using clear-text protocols is security-sensitive",
        Justification = "The value is an event identifier compared verbatim (OpenID Back-Channel Logout 1.0 Section 2.4), not an address anything connects to; the https spelling would be a different identifier no receiver recognises.")]
    public const string BackChannelLogout = "http://schemas.openid.net/event/backchannel-logout";
}
