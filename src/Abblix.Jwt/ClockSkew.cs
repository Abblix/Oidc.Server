// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// How far a token's timestamps may sit either side of this clock and still be honoured.
/// </summary>
/// <remarks>
/// <para>
/// The two directions are separate numbers because only one of them is governed by anything. FAPI
/// 2.0 Security Profile section 5.3.2.1 speaks exclusively of <c>iat</c> and <c>nbf</c> "in the
/// future"; <c>exp</c> appears nowhere in that section, so how long a token stays usable past its
/// stated end is this library's question to answer and a profile's to leave alone.
/// </para>
/// <para>
/// They travel as one type so that a caller passing a tolerance passes both halves or neither. A
/// value carrying one half is indistinguishable from a deliberate asymmetry, which is what the
/// profile below expresses on purpose.
/// </para>
/// </remarks>
public readonly record struct ClockSkew
{
    /// <summary>
    /// No tolerance in either direction, and what a caller gets by saying nothing.
    /// </summary>
    /// <remarks>
    /// A default that granted time would widen an expiry check for every caller that never asked -
    /// including one enforcing a deadline of its own, which is what most callers of this type are
    /// doing. A tolerance is granted deliberately or not at all: a deployment-wide answer belongs to
    /// the security profile a host opts into, and a number a profile requires is the profile's to
    /// supply.
    /// </remarks>
    public static readonly ClockSkew None = TimeSpan.Zero;

    /// <summary>
    /// What FAPI 2.0 Security Profile section 5.3.2.1 asks a server to accept: an <c>iat</c> or
    /// <c>nbf</c> "between 0 and 10 seconds in the future".
    /// </summary>
    /// <remarks>
    /// The asymmetry is the specification's, not a choice made here. That sentence speaks only of
    /// the future direction, so nothing in it extends the life of a token past the <c>exp</c> its
    /// own issuer chose - which is a deadline this server has no reason to move.
    /// </remarks>
    public static readonly ClockSkew Fapi2 = new()
    {
        Past = TimeSpan.Zero,
        Future = TimeSpan.FromSeconds(10),
    };

    /// <summary>
    /// The furthest anything may be dated under FAPI 2.0 Security Profile section 5.3.2.1, which
    /// requires a server to "reject JWTs with an <c>iat</c> or <c>nbf</c> timestamp greater than 60
    /// seconds in the future".
    /// </summary>
    /// <remarks>
    /// A bound on whatever a caller asks for, which is why it is separate from <see cref="Fapi2"/>
    /// rather than folded into it. Note 3 of that section says the number is in the document "to
    /// prevent implementations switching off <c>iat</c> and <c>nbf</c> checks completely", so it
    /// belongs to the profile: a deployment outside one answers to RFC 7523 Section 3, which names
    /// no bound at all.
    ///
    /// The quoted sentence governs the forward direction; holding the backward one to the same
    /// number is this server's decision rather than the specification's. A profile distrusting a
    /// clock past some point one way has no reason to trust it further the other, and the alternative
    /// is a ceiling that reads as a bound on the tolerance while leaving half of it unbounded.
    /// </remarks>
    public static readonly TimeSpan Fapi2Ceiling = TimeSpan.FromSeconds(60);

    /// <summary>
    /// How far into the past a timestamp may reach and still be honoured: how long a token stays
    /// usable after the <c>exp</c> it carries.
    /// </summary>
    public required TimeSpan Past { get; init; }

    /// <summary>
    /// How far into the future a timestamp may reach and still be honoured: how far off a token's
    /// <c>nbf</c> or <c>iat</c> may be dated. This is the direction FAPI 2.0 section 5.3.2.1 speaks
    /// of, and the only one any specification here bounds.
    /// </summary>
    public required TimeSpan Future { get; init; }

    /// <summary>
    /// One number means the same tolerance either way, so a caller holding a single window assigns
    /// it directly.
    /// </summary>
    /// <remarks>
    /// Implicit because the conversion loses nothing and cannot fail: a caller with one number has
    /// said what both halves are. The asymmetry belongs to a profile that prescribes one, never to
    /// a value somebody typed - a host naming one window means it in each direction, and having to
    /// spell that out is the sort of ceremony that gets one half set and the other forgotten.
    /// </remarks>
    /// <param name="symmetric">The tolerance to apply either way.</param>
    public static implicit operator ClockSkew(TimeSpan symmetric) => new() { Past = symmetric, Future = symmetric };

    /// <summary>
    /// Why a token's timestamps are refused at <paramref name="now"/>, or null where this tolerance
    /// admits them.
    /// </summary>
    /// <remarks>
    /// The comparison belongs here rather than to whoever validates, because more than one caller
    /// asks it: a token is checked once against the tolerance it arrived under, and again wherever a
    /// tighter one turns out to apply. Two copies would part company on the boundaries, which is
    /// where they are least likely to be noticed - expiry is compared with <c>&lt;=</c>, so a token
    /// exactly its whole tolerance past the end is already expired, while one exactly the whole
    /// tolerance ahead is still accepted.
    ///
    /// The order is deliberate: a token both post-dated and expired answers "not yet valid", which
    /// is what its sender meant to send and what tells them so.
    /// </remarks>
    /// <param name="now">The instant the timestamps are judged against.</param>
    /// <param name="notBefore">When the token says it starts, if it says.</param>
    /// <param name="expiresAt">When the token says it ends, if it says.</param>
    /// <param name="issuedAt">When the token says it was minted, if it says.</param>
    public string? WhyRefused(
        DateTimeOffset now,
        DateTimeOffset? notBefore,
        DateTimeOffset? expiresAt,
        DateTimeOffset? issuedAt)
    {
        var future = now + Future;

        if (notBefore.HasValue && future < notBefore.Value.ToUniversalTime())
            return "Token not yet valid";

        if (expiresAt.HasValue && expiresAt.Value.ToUniversalTime() <= now - Past)
            return "Token has expired";

        if (issuedAt.HasValue && future < issuedAt.Value.ToUniversalTime())
            return "Token issued in the future";

        return null;
    }

    /// <summary>
    /// This tolerance with neither direction exceeding <paramref name="ceiling"/>, or unchanged
    /// where there is no ceiling to hold it to.
    /// </summary>
    /// <param name="ceiling">The furthest either direction may reach, or null for no bound.</param>
    public ClockSkew BoundedBy(TimeSpan? ceiling)
    {
        if (ceiling is not { } bound)
            return this;

        return new()
        {
            Past = Min(Past, bound),
            Future = Min(Future, bound),
        };
    }

    private static TimeSpan Min(TimeSpan window, TimeSpan bound) => bound < window ? bound : window;
}
