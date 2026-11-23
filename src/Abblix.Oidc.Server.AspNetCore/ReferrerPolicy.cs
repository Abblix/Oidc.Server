// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// The referrer policy of a response whose address or content carries a value no other site may learn: the
/// form_post page with the authorization response (RFC 9700 section 4.2.4) and the redirect to the logout
/// confirmation page with the request it asks about.
/// </summary>
internal static class ReferrerPolicy
{
    /// <summary>
    /// The header, which the framework names no constant for.
    /// </summary>
    public const string HeaderName = "Referrer-Policy";

    /// <summary>
    /// No request the page leads to sends a referrer.
    /// </summary>
    public const string NoReferrer = "no-referrer";
}
