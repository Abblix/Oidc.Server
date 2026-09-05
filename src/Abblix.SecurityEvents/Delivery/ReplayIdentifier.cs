// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ReplayPrevention;

namespace Abblix.SecurityEvents.Delivery;

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
