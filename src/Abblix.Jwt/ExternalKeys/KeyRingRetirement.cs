// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Removes from the store the keys whose successor has served long enough that nobody can still hold a token
/// they produced.
/// </summary>
/// <param name="schedule">The clock, how long a new key takes to reach every consumer, and how long a retired one is
/// kept.</param>
internal sealed class KeyRingRetirement(KeyRingSchedule schedule)
{
    /// <summary>
    /// Drops the keys whose last token has expired, and returns what remains.
    /// </summary>
    /// <remarks>
    /// Without this the ring only grows, and every refresh opens one more envelope, which is a custodian
    /// round-trip apiece.
    /// <para>
    /// A key retires when its successor starts signing, not when the successor appears, so the moment is derived
    /// rather than stored: the successor is active at its own creation plus the propagation window, and from then
    /// the retired key only has to outlive the tokens it already signed. Every pod computes the same instant from
    /// the same entries, so they need no agreement about it, and a removal race is harmless - two pods dropping
    /// the same expired key is the outcome either wanted.
    /// </para>
    /// </remarks>
    public async Task<IReadOnlyList<OpenedKey>> RetireExpiredAsync(
        IReadOnlyList<OpenedKey> opened,
        IKeyRingStore source,
        CancellationToken cancellationToken)
    {
        var now = schedule.Now;
        var propagation = schedule.Propagation;
        var keepRetiredFor = schedule.KeepRetiredFor;

        // Retirement is decided per ROLE, and a key is kept if any role it serves still needs it. That is what
        // makes an unrestricted key (no `use`, so it serves both) safe to hold: it leaves only once BOTH roles
        // have moved on, and a role nobody mints for - encryption, when no encryption algorithm is named - keeps
        // it indefinitely, which is correct, since it is the only key that role has.
        var expired = new HashSet<string>(opened.Select(key => key.Id));

        foreach (var usage in new[] { PublicKeyUsages.Signature, PublicKeyUsages.Encryption })
        {
            // Oldest first, so a key's successor is the next minted key along. An adopted key is never the
            // successor of another: adopted keys of one role are all replaced by the first minted key, and taking
            // one for the next would retire the other as soon as the minted key took over, while the tokens it
            // signed still had their lifetime to run. A key with no minted key after it has no successor and never
            // retires: it is the key currently producing, the one about to, or the adopted key of a role nobody
            // mints for.
            var byOldest = opened
                .Where(key => OpenedKey.Serves(key.Key, usage))
                .OrderBy(key => key.CreatedAt)
                .ToList();

            for (var index = 0; index < byOldest.Count; index++)
            {
                var key = byOldest[index];
                var successor = byOldest.Skip(index + 1).FirstOrDefault(later => !later.IsAdopted);

                if (successor is null || now <= successor.CreatedAt + propagation + keepRetiredFor)
                    expired.Remove(key.Id);
            }
        }

        var live = new List<OpenedKey>(opened.Count);
        foreach (var key in opened)
        {
            if (!expired.Contains(key.Id))
            {
                live.Add(key);
                continue;
            }

            await source.RemoveAsync(key.Id, cancellationToken);
        }

        return live;
    }
}
