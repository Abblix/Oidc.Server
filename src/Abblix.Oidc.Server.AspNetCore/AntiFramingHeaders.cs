// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.AspNetCore;

/// <summary>
/// Header values that forbid a self-rendered HTML page (such as the form_post auto-submit page) from being
/// embedded in another origin's frame, defending against clickjacking as required by the OAuth 2.0 Security
/// Best Current Practice (RFC 9700, Section 4.16). Single source of truth shared by both transport adapters,
/// paired with the framework's <c>HeaderNames</c> constants for the header names at the call site.
/// </summary>
public static class AntiFramingHeaders
{
    /// <summary>
    /// Content-Security-Policy value that denies every framing ancestor. Covers modern user agents.
    /// </summary>
    public const string ContentSecurityPolicy = "frame-ancestors 'none'";

    /// <summary>
    /// X-Frame-Options value that denies all framing. Covers legacy user agents that predate CSP frame-ancestors.
    /// </summary>
    public const string XFrameOptions = "DENY";
}
