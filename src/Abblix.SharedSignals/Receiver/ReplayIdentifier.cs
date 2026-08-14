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

namespace Abblix.SharedSignals.Receiver;

/// <summary>
/// Composes what a receiver reserves in <see cref="IReplayCache"/> for one token.
/// </summary>
/// <remarks>
/// Every receiver in this package answers the same question of the cache and must answer it the
/// same way, which is why the composition lives here rather than at each call site. Two receivers
/// deriving one rule separately do not fail on the day they disagree - they keep working, in
/// different key spaces, and the disagreement surfaces only when somebody tightens one of them.
/// </remarks>
public static class ReplayIdentifier
{
    /// <summary>
    /// Composes the identifier for a token, scoping its own identifier to its issuer.
    /// </summary>
    /// <param name="issuer">The <c>iss</c> claim of the token.</param>
    /// <param name="tokenId">The <c>jti</c> claim of the token.</param>
    /// <returns>The value to reserve.</returns>
    /// <remarks>
    /// The issuer belongs in the value because a <c>jti</c> is unique only "within a particular
    /// event feed" (RFC 8417 Section 2.2), so reserving the identifier alone would let one
    /// provider's token refuse another provider's. Escaping removes the separator from both halves,
    /// so two distinct pairs cannot compose onto one identifier - without it an issuer ending in
    /// the separator and a short identifier produce the same value as a shorter issuer and a longer
    /// identifier, and one provider could reserve another's.
    /// </remarks>
    public static string ForToken(string issuer, string tokenId)
        => $"{Uri.EscapeDataString(issuer)}{Separator}{Uri.EscapeDataString(tokenId)}";

    /// <summary>
    /// Parts the two halves. Any character would do once both are escaped; this one is chosen
    /// because <see cref="Uri.EscapeDataString(string)"/> is documented to escape it, which is what
    /// makes the composition unambiguous.
    /// </summary>
    private const string Separator = ":";
}
