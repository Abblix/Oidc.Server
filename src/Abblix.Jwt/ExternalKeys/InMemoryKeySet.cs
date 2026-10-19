// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The keys the in-memory ring minted, rotated on its policy, each operation under one lock.
/// </summary>
/// <param name="policy">What to mint, how often, and how long to keep a retired key.</param>
/// <param name="timeProvider">When a rotation happens and which key produces.</param>
internal sealed class InMemoryKeySet(LocalKeys policy, TimeProvider timeProvider)
{
    private readonly InMemoryKeyMinting _minting = new(policy);
    private readonly List<InMemoryMintedKey> _keys = [];

    /// <summary>
    /// Guards minting and retirement, and the clock reads they are made at. Reads take it too: a caller must not
    /// observe the set mid-rotation, with the retired key already gone and its replacement not yet added, nor
    /// choose its key as of a moment before a rotation another caller made first.
    /// </summary>
    private readonly Lock _gate = new();

    /// <summary>
    /// Rotates the set, then answers the keys of <paramref name="usage"/>, the one producing now first.
    /// </summary>
    /// <param name="usage">The role of the keys.</param>
    /// <param name="includePrivateKeys">Whether the private halves are kept.</param>
    /// <param name="propagation">How long a new key is announced before it produces.</param>
    public IEnumerable<JsonWebKey> RotateAndServe(string usage, bool includePrivateKeys, TimeSpan propagation)
    {
        using (_gate.EnterScope())
        {
            RotateHeld(timeProvider.GetUtcNow());

            return _keys
                .Where(minted => minted.Key.Usage == usage)
                .ToList()
                .ProduceFirst(minted => minted.CreatedAt, timeProvider.GetUtcNow(), propagation)
                .Select(minted => minted.Key.Sanitize(includePrivateKeys))
                .ToList();
        }
    }

    /// <summary>
    /// When the newest key of <paramref name="usage"/> was minted, or null when it has none.
    /// </summary>
    public DateTimeOffset? NewestCreatedAt(string usage)
    {
        using (_gate.EnterScope())
        {
            return _keys.Where(minted => minted.Key.Usage == usage).Max(minted => (DateTimeOffset?)minted.CreatedAt);
        }
    }

    /// <summary>
    /// Mints the keys due now and drops those retired long enough.
    /// </summary>
    public void Rotate()
    {
        using (_gate.EnterScope())
        {
            RotateHeld(timeProvider.GetUtcNow());
        }
    }

    private void RotateHeld(DateTimeOffset now)
    {
        // Taken whole first, so adding never runs while the minting still reads the list it adds to
        _keys.AddRange(_minting.Due(_keys, now).ToList());
        RetireExpired(now);
    }

    /// <summary>
    /// Drops keys that have been retired long enough that nothing they produced can still be in use.
    /// </summary>
    private void RetireExpired(DateTimeOffset now)
    {
        foreach (var usage in _keys.Select(minted => minted.Key.Usage).Distinct().ToList())
        {
            // The newest key of a role is never dropped, however old it is: dropping it would leave the role
            // with nothing to produce with, which is worse than serving one past its rotation date.
            var newest = _keys.Where(minted => minted.Key.Usage == usage).Max(minted => minted.CreatedAt);

            _keys.RemoveAll(minted =>
                minted.Key.Usage == usage &&
                minted.CreatedAt != newest &&
                now - minted.CreatedAt > policy.RotateEvery + policy.KeepRetiredFor);
        }
    }
}
