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
