// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.LogoutNotification;

namespace Abblix.Oidc.Server.AspNetCore.Formatters;

/// <summary>
/// The policy of the page that signs the end user out of the clients of their session by loading each client's
/// front-channel logout address in a frame (OpenID Connect Front-Channel Logout 1.0 section 3), shared by both
/// transport adapters.
/// </summary>
internal static class FrontChannelLogoutPage
{
    /// <summary>
    /// Lets the page run only its own nonce-marked script and style and frame only the clients' origins, and lets no
    /// other page frame it. The page is the end-session endpoint's answer to a top-level navigation, so a frame around
    /// it serves nobody, while RFC 9700 section 4.16 has the server prevent clickjacking of the pages it renders.
    /// </summary>
    /// <param name="response">The rendered page, with the nonce its script and style carry and the origins it frames.</param>
    public static string ContentSecurityPolicy(FrontChannelLogoutResponse response)
        => $"default-src 'none'; script-src 'nonce-{response.Nonce}'; style-src 'nonce-{response.Nonce}'; " +
           $"frame-src {string.Join(' ', response.FrameSources)}; {AntiFramingHeaders.ContentSecurityPolicy}";
}
