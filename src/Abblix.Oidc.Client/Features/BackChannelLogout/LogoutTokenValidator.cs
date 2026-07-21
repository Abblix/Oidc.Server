// Abblix OIDC Client Library
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

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.TokenValidation;

namespace Abblix.Oidc.Client.Features.BackChannelLogout;

/// <summary>
/// Validates Logout Tokens arriving at this client's back-channel logout endpoint.
/// </summary>
/// <param name="tokenVerifier">
/// Establishes that the token is the provider's and addressed to this client, which is steps 2 to 4.
/// </param>
/// <param name="replayGuard">Remembers tokens already acted on, which is step 8.</param>
public sealed class LogoutTokenValidator(
    IProviderTokenVerifier tokenVerifier,
    ILogoutTokenReplayGuard replayGuard) : ILogoutTokenValidator
{
    /// <inheritdoc />
    public async Task<LogoutNotification> ValidateAsync(
        string logoutToken, CancellationToken cancellationToken = default)
    {
        // Steps 2, 3 and 4 of section 2.6, which the specification defines by reference: the signature, the
        // algorithm, and the iss, aud, iat and exp claims are each validated "in the same way" as for an ID
        // Token. Step 1 is decryption, which does not arise: this client registers no encryption algorithm
        // for the endpoint, so an encrypted token is one it never asked for and the JOSE layer refuses.
        JsonWebToken token;
        try
        {
            token = await tokenVerifier.VerifyAsync(logoutToken, cancellationToken);
        }
        catch (ProviderTokenValidationException exception)
        {
            throw new LogoutTokenValidationException(
                $"The Logout Token was rejected: {exception.Message}");
        }

        // From here the claims are the issuer's statements rather than the sender's.
        RequireSubjectOrSession(token);
        RequireLogoutEvent(token);
        RefuseNonce(token);

        await RefuseReplayAsync(token, cancellationToken);

        return new LogoutNotification(
            token.Payload.Issuer
            ?? throw new LogoutTokenValidationException("The Logout Token names no issuer."),
            token.Payload.Subject,
            token.Payload.SessionId,
            token.Payload.JwtId);
    }

    /// <summary>
    /// Step 8: "Optionally verify that another Logout Token with the same jti value has not been recently
    /// received."
    /// </summary>
    /// <remarks>
    /// Taken up rather than skipped, because the request carrying this token is unauthenticated and the
    /// token is a bearer credential: anyone who observes one can post it again, and within the short window
    /// section 4 asks providers to use, nothing but a record of what has been seen tells a replay from the
    /// original.
    /// The token identifier is required here as a consequence. Section 2.4 lists <c>jti</c> among the
    /// REQUIRED claims of a Logout Token, which is a duty on the issuer; refusing a token without one is
    /// ours, and it follows from taking step 8 at all - a token that cannot be recorded is one that passes
    /// the guard by being unidentifiable, which is worse than having no guard.
    /// </remarks>
    private async Task RefuseReplayAsync(JsonWebToken token, CancellationToken cancellationToken)
    {
        if (token.Payload.JwtId is not { Length: > 0 } tokenId)
        {
            throw new LogoutTokenValidationException(
                "The Logout Token carries no jti, so it cannot be told apart from a replay of itself.");
        }

        // The expiry the verifier already accepted. Nothing needs remembering past it: an expired token is
        // refused before this guard is reached.
        var expiresAt = token.Payload.ExpiresAt
                        ?? throw new LogoutTokenValidationException(
                            "The Logout Token carries no expiry, so there is no window to remember it for.");

        if (!await replayGuard.TryRecordAsync(tokenId, expiresAt, cancellationToken))
        {
            throw new LogoutTokenValidationException(
                "This Logout Token has already been acted on, so it is a replay.");
        }
    }

    /// <summary>
    /// Step 5: "Verify that the Logout Token contains a sub Claim, a sid Claim, or both."
    /// </summary>
    /// <remarks>
    /// A token carrying neither says a session ended without saying whose, which section 2.7 leaves nothing
    /// to act on: the RP is asked to "locate the session(s) identified by the iss and sub Claims and/or the
    /// sid Claim". An RP that accepted it would either do nothing, and answer 200 to a request it did not
    /// honour, or log out every session it holds for that issuer.
    /// </remarks>
    private static void RequireSubjectOrSession(JsonWebToken token)
    {
        if (string.IsNullOrEmpty(token.Payload.Subject) && string.IsNullOrEmpty(token.Payload.SessionId))
        {
            throw new LogoutTokenValidationException(
                "The Logout Token names neither a subject nor a session, so there is nothing to end.");
        }
    }

    /// <summary>
    /// Step 6: "Verify that the Logout Token contains an events Claim whose value is JSON object containing
    /// the member name http://schemas.openid.net/event/backchannel-logout."
    /// </summary>
    /// <remarks>
    /// This is what makes the token a logout notification rather than some other token the same issuer signed
    /// for the same audience. Without the check, any such token - an ID Token above all - would be accepted
    /// here and log the user out, which is the cross-JWT confusion section 4.1 names.
    /// </remarks>
    private static void RequireLogoutEvent(JsonWebToken token)
    {
        if (token.Payload[JwtClaimTypes.Events] is not JsonObject events)
        {
            throw new LogoutTokenValidationException(
                "The Logout Token carries no events claim, so it does not state a back-channel logout.");
        }

        if (!events.ContainsKey(LogoutTokenClaims.BackChannelLogoutEvent))
        {
            throw new LogoutTokenValidationException(
                "The events claim of the Logout Token does not name the back-channel logout event.");
        }
    }

    /// <summary>
    /// Step 7: "Verify that the Logout Token does not contain a nonce Claim."
    /// </summary>
    /// <remarks>
    /// The prohibition runs the other way round, and section 2.4 says why: a nonce "is prohibited to make a
    /// Logout Token syntactically invalid if used in a forged Authentication Response in place of an ID
    /// Token". So refusing it here is this endpoint keeping its half of an agreement that protects the
    /// authorization callback, not this endpoint protecting itself.
    /// </remarks>
    private static void RefuseNonce(JsonWebToken token)
    {
        if (token.Payload.Nonce is not null)
        {
            throw new LogoutTokenValidationException(
                "The Logout Token carries a nonce, which a Logout Token must not.");
        }
    }
}
