// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The keys a ring has opened, held in memory for signing and decryption, and the answers read off them.
/// </summary>
/// <param name="schedule">The clock and the propagation window that decide which key produces.</param>
internal sealed class HeldKeys(KeyRingSchedule schedule)
{
    private volatile IReadOnlyList<OpenedKey> _keys = [];

    /// <summary>
    /// Returns the keys for a role, produce-first: the active one leads and the rest trail, so the produce role
    /// takes the active key while every key stays published for consumers.
    /// </summary>
    /// <param name="usage">Which role to serve, signature or encryption.</param>
    /// <param name="includePrivateKeys">Whether the caller needs the private half, which only signing and
    /// decryption do. Publication must not.</param>
    public IEnumerable<JsonWebKey> Get(string usage, bool includePrivateKeys)
        => _keys
            .Where(opened => OpenedKey.Serves(opened.Key, usage))
            .ToList()
            .ProduceFirst(opened => opened.CreatedAt, schedule.Now, schedule.Propagation)
            .Select(opened => opened.Key.Sanitize(includePrivateKeys));

    /// <inheritdoc />
    /// <remarks>
    /// Read off the keys this instance has opened, which is what it would serve if asked right now, rather than
    /// off the store: a custodian that cannot be reached must not read as a ring that has stopped rotating.
    /// </remarks>
    public DateTimeOffset? NewestKeyCreatedAt(string usage)
        => _keys
            .Where(opened => OpenedKey.Serves(opened.Key, usage))
            .Max(opened => (DateTimeOffset?)opened.CreatedAt);

    /// <summary>Replaces the held keys with the set a refresh opened, in one write the readers see whole.</summary>
    public void Replace(IReadOnlyList<OpenedKey> keys) => _keys = keys;
}
