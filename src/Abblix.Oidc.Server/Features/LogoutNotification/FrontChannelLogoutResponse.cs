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
/// Represents the response for a front-channel logout page in OpenID Connect.
/// Contains complete HTML content with CSP nonce already injected.
/// </summary>
/// <param name="HtmlContent">The complete HTML content ready to be rendered.</param>
/// <param name="Nonce">The CSP nonce value used in the HTML for script-src and style-src directives.</param>
/// <param name="FrameSources">Unique origins for CSP frame-src directive.</param>
public record FrontChannelLogoutResponse(string HtmlContent, string Nonce, IReadOnlyList<string> FrameSources);
