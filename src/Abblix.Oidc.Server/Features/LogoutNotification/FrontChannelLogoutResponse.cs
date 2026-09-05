// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Features.LogoutNotification;

/// <summary>
/// Represents the response for a front-channel logout page in OpenID Connect.
/// Contains complete HTML content with CSP nonce already injected.
/// </summary>
/// <param name="HtmlContent">The complete HTML content ready to be rendered.</param>
/// <param name="Nonce">The CSP nonce value used in the HTML for script-src and style-src directives.</param>
/// <param name="FrameSources">Unique origins for CSP frame-src directive.</param>
public record FrontChannelLogoutResponse(string HtmlContent, string Nonce, IReadOnlyList<string> FrameSources);
