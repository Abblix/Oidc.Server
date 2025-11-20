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

using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// Represents a backchannel authentication request as part of the Client-Initiated Backchannel Authentication (CIBA)
/// protocol.
/// This request facilitates the authentication of users without requiring immediate interaction with their devices,
/// allowing for a more flexible and user-friendly authentication experience.
/// </summary>
/// <param name="AuthorizedGrant">
/// The authorized grant associated with this authentication request,
/// containing details about the user's authorization context.
/// </param>
/// <param name="ExpiresAt">
/// The absolute time when this backchannel authentication request expires.
/// </param>
public record BackChannelAuthenticationRequest(AuthorizedGrant AuthorizedGrant, DateTimeOffset ExpiresAt)
{
    /// <summary>
    /// Specifies the next time the client should poll for updates regarding the authentication request.
    /// This helps manage the timing of polling requests efficiently.
    /// </summary>
    public DateTimeOffset? NextPollAt { get; set; }

    /// <summary>
    /// Indicates the current status of the backchannel authentication request.
    /// Defaults to Pending, reflecting that the request has not yet been resolved.
    /// </summary>
    public BackChannelAuthenticationStatus Status { get; set; } = BackChannelAuthenticationStatus.Pending;

    /// <summary>
    /// The client notification endpoint for ping mode.
    /// Populated from client configuration when ping mode is used.
    /// </summary>
    public Uri? ClientNotificationEndpoint { get; set; }

    /// <summary>
    /// The client notification token for ping mode.
    /// Provided by the client in the authentication request for secure notification delivery.
    /// </summary>
    public string? ClientNotificationToken { get; set; }
}
