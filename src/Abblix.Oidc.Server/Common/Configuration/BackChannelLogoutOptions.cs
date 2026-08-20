// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Back-channel logout settings for a single client, as defined by the OpenID Connect Back-Channel Logout 1.0
/// specification. The OP delivers a signed logout token directly (server-to-server) to the configured endpoint
/// when an end-session occurs, bypassing the user agent.
/// </summary>
/// <param name="Uri">The client's back-channel logout endpoint that receives the logout token.</param>
/// <param name="RequiresSessionId">
/// When <c>true</c>, the logout token must include the <c>sid</c> claim so the client can scope the
/// invalidation to a specific session.
/// </param>
public record BackChannelLogoutOptions(Uri Uri, bool RequiresSessionId = true)
{
    /// <summary>
    /// The client's back-channel logout endpoint that receives the signed logout token.
    /// </summary>
    public Uri Uri { get; init; } = Uri;

    /// <summary>
    /// When <c>true</c>, the issued logout token must carry the <c>sid</c> claim so the client can
    /// invalidate the matching session rather than every session of the user.
    /// </summary>
    public bool RequiresSessionId { get; init; } = RequiresSessionId;

    /// <summary>
    /// Lifetime of the issued logout token. Kept short to limit the replay window for the token,
    /// since back-channel logout tokens cross the network as bearer credentials.
    /// </summary>
    public TimeSpan LogoutTokenExpiresIn { get; set; } = TimeSpan.FromMinutes(5);
}
