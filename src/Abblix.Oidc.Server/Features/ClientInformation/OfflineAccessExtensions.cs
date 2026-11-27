// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// The two questions every reader of an <see cref="OfflineAccess"/> asks, answered in one place, and whether one value
/// gives a client as much as another.
/// </summary>
internal static class OfflineAccessExtensions
{
    /// <summary>
    /// Whether the client may receive offline access at all.
    /// </summary>
    public static bool IsAllowed(this OfflineAccess offlineAccess) => offlineAccess switch
    {
        OfflineAccess.Disabled => false,
        OfflineAccess.ConsentRequired or OfflineAccess.Allowed => true,
        _ => throw new ArgumentOutOfRangeException(nameof(offlineAccess), offlineAccess, null),
    };

    /// <summary>
    /// Whether the client receives offline access without asking for consent with <c>prompt=consent</c>.
    /// </summary>
    public static bool IsAllowedWithoutConsentPrompt(this OfflineAccess offlineAccess) => offlineAccess switch
    {
        OfflineAccess.Disabled or OfflineAccess.ConsentRequired => false,
        OfflineAccess.Allowed => true,
        _ => throw new ArgumentOutOfRangeException(nameof(offlineAccess), offlineAccess, null),
    };

    /// <summary>
    /// Whether <paramref name="granted"/> gives a client everything <paramref name="asked"/> would: each of the two
    /// questions above answered yes for <paramref name="asked"/> is answered yes for <paramref name="granted"/> too.
    /// </summary>
    public static bool Covers(this OfflineAccess granted, OfflineAccess asked)
        => (!asked.IsAllowed() || granted.IsAllowed())
           && (!asked.IsAllowedWithoutConsentPrompt() || granted.IsAllowedWithoutConsentPrompt());
}
