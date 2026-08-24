// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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

    /// <summary>
    /// The end user the request named through <c>id_token_hint</c>, spelled as the requesting client sees
    /// them, or <c>null</c> when the request named nobody.
    /// </summary>
    /// <remarks>
    /// Recorded here rather than compared once and discarded, because in a decoupled flow the end user
    /// authenticates long after the request was made: the session that answers it arrives through
    /// <see cref="Interfaces.IAuthenticationCompletionHandler.CompleteAsync"/>, and OpenID Connect Core 1.0
    /// Section 3.1.2.2 forbids answering for anyone else. Without this the comparison would have nothing left
    /// to compare against by the time there is a session to judge.
    /// </remarks>
    public string? RequestedSubject { get; set; }
}
