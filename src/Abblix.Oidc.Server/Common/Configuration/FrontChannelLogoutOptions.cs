// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Front-channel logout settings for a single client, as defined by the OpenID Connect Front-Channel Logout 1.0
/// specification. Tells the authorization server which URL to load in a hidden iframe during end-session
/// processing and whether the iframe URL must carry the user's session identifier.
/// </summary>
/// <param name="Uri">The client's front-channel logout endpoint, loaded in a hidden iframe at the OP.</param>
/// <param name="RequiresSessionId">
/// When <c>true</c>, the OP appends <c>iss</c> and <c>sid</c> query parameters to <paramref name="Uri"/>
/// so the client can scope the logout to the correct session.
/// </param>
public record FrontChannelLogoutOptions(Uri Uri, bool RequiresSessionId = true);
