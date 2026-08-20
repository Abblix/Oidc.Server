// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Orders a set of key versions so the one to produce with leads: whoever signs or encrypts takes the first key
/// for an algorithm, while every version stays published so consumers can still verify or decrypt.
/// </summary>
/// <remarks>
/// This is the whole of what makes a rollover cause no verification failure, and it is the same arithmetic
/// wherever the versions come from: a custodian enumerating them, or a key ring the library owns. It is a pure
/// function of the creation times and the propagation window, so every pod derives the identical answer with no
/// coordination.
/// </remarks>
public static class ProduceFirstOrdering
{
    /// <summary>
    /// Returns the versions with the active one first and the rest trailing newest-first.
    /// </summary>
    /// <typeparam name="T">The version type, whatever carries a creation time.</typeparam>
    /// <param name="versions">The versions to order.</param>
    /// <param name="createdAt">Reads a version's creation time.</param>
    /// <param name="now">The current time.</param>
    /// <param name="propagation">How long a version stays announced before it starts producing, which is also the
    /// max-age the server puts on its JWKS response, so a client that honours it holds the key before it meets a
    /// token signed with it.</param>
    /// <returns>The versions, produce-first.</returns>
    /// <remarks>
    /// The active version is the newest one already past <paramref name="propagation"/>. If none has cleared it
    /// yet (bootstrap: the very first version is still fresh), the newest overall leads, since there is no older
    /// version a client could be holding instead.
    /// </remarks>
    public static IEnumerable<T> ProduceFirst<T>(
        this IReadOnlyList<T> versions,
        Func<T, DateTimeOffset> createdAt,
        DateTimeOffset now,
        TimeSpan propagation)
    {
        if (versions.Count <= 1)
            return versions;

        // Sort newest-first, then lead with the active version. The rest keep newest-first order. Selection is
        // index-based rather than by reference, since a version may be a value type for which ReferenceEquals is
        // meaningless.
        var byNewest = versions.OrderByDescending(createdAt).ToList();
        var activeIndex = byNewest.FindIndex(version => propagation <= now - createdAt(version));
        if (activeIndex < 0)
            activeIndex = 0;

        return byNewest
            .Skip(activeIndex)
            .Take(1)
            .Concat(byNewest.Take(activeIndex))
            .Concat(byNewest.Skip(activeIndex + 1));
    }
}
