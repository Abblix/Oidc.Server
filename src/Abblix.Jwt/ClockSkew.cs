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
    /// The tolerance a caller gets by saying nothing: the same each way, and the value the
    /// platform's own token validator uses.
    /// </summary>
    /// <remarks>
    /// The number belongs to no specification and is not meant to: it is the value a caller who has
    /// never thought about clock offset already expects, so adopting it changes nothing for anyone
    /// moving here from the platform's own validator. A tolerance a profile requires is the
    /// profile's to name - taking one of those numbers as the general default would hold every
    /// caller to a profile they never selected.
    /// </remarks>
    public static readonly ClockSkew Default = TimeSpan.FromMinutes(5);

    /// <summary>
    /// No tolerance in either direction, for a caller measuring an instant rather than allowing for
    /// a clock that disagrees.
    /// </summary>
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
