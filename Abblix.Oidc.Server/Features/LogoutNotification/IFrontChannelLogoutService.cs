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
