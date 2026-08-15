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

using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SecurityEvents.BackChannelLogout;

/// <summary>
/// Validates Logout Tokens arriving at this receiver's back-channel logout endpoint.
/// </summary>
/// <remarks>
/// Steps 1 to 7 of OpenID Connect Back-Channel Logout 1.0 Section 2.6 are the profile's, which is
/// why this class is short: the signature, the algorithm and the iss, aud, iat and exp claims are
/// the steps the specification defines by reference to ID Token validation, and the profile
/// carries them along with the logout event, the absent nonce and the subject or session. What is
/// left here is step 8 and the notification the host acts on.
/// <para>
/// Step 1, decryption, does not arise: this receiver registers no encryption algorithm for the
/// endpoint, so an encrypted token is one it never asked for and the JOSE layer refuses.
/// </para>
/// </remarks>
/// <param name="validator">
/// The validation pipeline, resolved from this receiver's own named profile
/// (<see cref="ValidationProfileKeys.LogoutToken"/>) - never the host's plain family,
/// which another consumer of security event tokens may have shaped to refuse every Logout Token.
/// </param>
/// <param name="options">What this receiver expects of every Logout Token.</param>
/// <param name="replayCache">Remembers tokens already acted on, which is step 8.</param>
public sealed class LogoutTokenValidator(
    [FromKeyedServices(ValidationProfileKeys.LogoutToken)] ISecurityEventTokenValidator validator,
    BackChannelLogoutValidationOptions options,
    IReplayCache replayCache) : ILogoutTokenValidator
{
    /// <inheritdoc />
    public async Task<LogoutNotification> ValidateAsync(
        string logoutToken, CancellationToken cancellationToken = default)
    {
        var verdict = await validator.ValidateAsync(logoutToken, options, cancellationToken);
        if (verdict.TryGetFailure(out var error))
            throw new LogoutTokenValidationException($"The Logout Token was rejected: {error.Description}");

        verdict.TryGetSuccess(out var validated);
        var token = validated!.Token;

        // From here the claims are the issuer's statements rather than the sender's.
        var issuer = token.Issuer
                     ?? throw new LogoutTokenValidationException("The Logout Token names no issuer.");

        await RefuseReplayAsync(issuer, token, cancellationToken);

        var payload = token.Token.Payload;
        return new LogoutNotification(issuer, payload.Subject, payload.SessionId, token.JwtId);
    }

    /// <summary>
    /// Step 8: "Optionally verify that another Logout Token with the same jti value has not been
    /// recently received."
    /// </summary>
    /// <remarks>
    /// Taken up rather than skipped, because the request carrying this token is unauthenticated and
    /// the token is a bearer credential: anyone who observes one can post it again, and within the
    /// short window Section 4 asks providers to use, nothing but a record of what has been seen
    /// tells a replay from the original.
    /// <para>
    /// What is reserved is composed by <see cref="ReplayIdentifier"/>, which both receivers in this
    /// package share: they reserve into one cache, so composing the value twice would be one rule
    /// with two derivations and no failure on the day they part.
    /// </para>
    /// <para>
    /// A token with no "jti" or no "exp" cannot reach this method - the profile's own steps require
    /// both - so the misses below are not the wire's shape but a weakened profile's, and they fail
    /// closed: a token that cannot be recorded is one that passes the guard by being
    /// unidentifiable, which is worse than having no guard.
    /// </para>
    /// </remarks>
    private async Task RefuseReplayAsync(
        string issuer, SecurityEventToken token, CancellationToken cancellationToken)
    {
        if (token.JwtId is not { Length: > 0 } tokenId)
        {
            throw new LogoutTokenValidationException(
                "The Logout Token carries no jti, so it cannot be told apart from a replay of itself.");
        }

        // The expiry the profile already accepted. Nothing needs remembering past it: an expired
        // token is refused before this guard is reached.
        var expiresAt = token.Token.Payload.ExpiresAt
                        ?? throw new LogoutTokenValidationException(
                            "The Logout Token carries no expiry, so there is no window to remember it for.");

        if (!await replayCache.TryReserveAsync(
                ReplayIdentifier.ForToken(issuer, tokenId), expiresAt, cancellationToken))
        {
            throw new LogoutTokenValidationException(
                "This Logout Token has already been acted on, so it is a replay.");
        }
    }
}
