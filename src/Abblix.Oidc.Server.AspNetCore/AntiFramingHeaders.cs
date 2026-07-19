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
