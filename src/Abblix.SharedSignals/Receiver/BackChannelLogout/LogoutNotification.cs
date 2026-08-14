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

using Abblix.Jwt;

namespace Abblix.SharedSignals.Receiver.BackChannelLogout;

/// <summary>
/// Which sessions a validated Logout Token says to end.
/// </summary>
/// <remarks>
/// What OpenID Connect Back-Channel Logout 1.0 Section 2.7 asks the RP to act on: "locate the
/// session(s) identified by the iss and sub Claims and/or the sid Claim", then "clear any state
/// associated with the identified session(s)". Acting is the host's, since only the host knows
/// where its sessions are kept.
/// </remarks>
/// <param name="Issuer">The provider that sent the notification.</param>
/// <param name="Subject">
/// The end-user whose sessions are ending, when the token named one. Every session this client
/// holds for that user at that issuer is meant, not one of them.
/// </param>
/// <param name="SessionId">
/// The single session that is ending, when the token named one. Narrower than the subject, and the
/// two may arrive together.
/// </param>
/// <param name="TokenId">The <c>jti</c> of the token that carried this notification.</param>
public sealed record LogoutNotification(
    string Issuer,
    string? Subject,
    string? SessionId,
    string? TokenId)
{
    /// <summary>
    /// Reports whether this notification is about the session <paramref name="identityToken"/>
    /// belongs to.
    /// </summary>
    /// <param name="identityToken">
    /// The ID Token of a session this client is holding, as validated when that session was
    /// established.
    /// </param>
    /// <returns>
    /// <c>true</c> when the notification names that session and nothing contradicts it.
    /// </returns>
    /// <remarks>
    /// Steps 9, 10 and 11 of OpenID Connect Back-Channel Logout 1.0 Section 2.6, which the
    /// specification introduces with "Optionally verify that the iss Logout Token Claim matches the
    /// iss Claim in an ID Token issued for the current session or a recent session", and likewise
    /// of any <c>sub</c> and any <c>sid</c>.
    /// They are offered here rather than performed during validation because they are questions
    /// about a session, and only the host knows which sessions it holds - Section 2.7 already makes
    /// it responsible for finding them. What the library can do is make the comparison one call
    /// rather than three hand-written string comparisons, which is where a case-insensitive or a
    /// null-tolerant one creeps in.
    /// Note what "matches" means for a claim the token did not carry: the notification names a
    /// subject or a session or both, and a claim it did not name places no restriction. A
    /// notification carrying only a subject is about every session this client holds for that user,
    /// which is exactly what a provider means by omitting the session identifier.
    /// </remarks>
    public bool Matches(JsonWebToken identityToken)
    {
        var payload = identityToken.Payload;

        return Equal(Issuer, payload.Issuer)
               && (Subject is null || Equal(Subject, payload.Subject))
               && (SessionId is null || Equal(SessionId, payload.SessionId));
    }

    /// <summary>
    /// Compares two identifiers exactly, since nothing in the specification licenses folding them
    /// together.
    /// </summary>
    private static bool Equal(string? left, string? right)
        => left is not null && string.Equals(left, right, StringComparison.Ordinal);
}
