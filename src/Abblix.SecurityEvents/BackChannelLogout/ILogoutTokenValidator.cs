// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// Validates the Logout Token a provider posts to this receiver to say a session has ended
/// (OpenID Connect Back-Channel Logout 1.0 section 2.6).
/// </summary>
/// <remarks>
/// The request carrying this token is unauthenticated and comes from a caller this receiver never spoke to
/// first, so the token is the only thing vouching for it. Section 4: "The signed Logout Token is required in
/// the logout request to prevent denial of service attacks by enabling the RP to verify that the logout
/// request is coming from a legitimate party." Every check below exists because anyone on the network can
/// make this call.
/// </remarks>
public interface ILogoutTokenValidator
{
    /// <summary>
    /// Validates <paramref name="logoutToken"/> and returns which sessions it says to end.
    /// </summary>
    /// <param name="logoutToken">The encoded Logout Token from the <c>logout_token</c> parameter.</param>
    /// <param name="cancellationToken">Cancels the key-set and metadata reads this may need.</param>
    /// <returns>What the token says to act on.</returns>
    /// <remarks>
    /// Steps 8 to 11 of section 2.6 are each introduced with "Optionally", and each needs something only the
    /// host has: a record of tokens recently seen, or the ID Token of the session being ended. They are left
    /// to the host, which holds the sessions this notification is about, and which section 2.7 makes
    /// responsible for locating them anyway.
    /// </remarks>
    /// <exception cref="LogoutTokenValidationException">
    /// The token failed a validation step. Section 2.6: "If any of the validation steps fails, reject the
    /// Logout Token and return an HTTP 400 Bad Request error."
    /// </exception>
    Task<LogoutNotification> ValidateAsync(
        string logoutToken, CancellationToken cancellationToken = default);
}
