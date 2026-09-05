// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Service for generating front-channel logout HTML responses in accordance with
/// OpenID Connect Front-Channel Logout 1.0 specification.
/// </summary>
public interface IFrontChannelLogoutService
{
    /// <summary>
    /// Generates the HTML response for a front-channel logout page.
    /// The response contains iframes for each logout URI and an optional redirect script.
    /// </summary>
    /// <param name="postLogoutRedirectUri">The URI to redirect to after all iframes have loaded, or null for no redirect.</param>
    /// <param name="frontChannelLogoutUris">The list of client logout URIs to embed as iframes.</param>
    /// <returns>A response containing complete HTML with CSP nonce already injected.</returns>
    FrontChannelLogoutResponse GetFrontChannelLogoutResponse(
        Uri? postLogoutRedirectUri,
        IList<Uri> frontChannelLogoutUris);
}
