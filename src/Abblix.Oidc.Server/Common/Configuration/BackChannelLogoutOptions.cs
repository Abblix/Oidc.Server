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
