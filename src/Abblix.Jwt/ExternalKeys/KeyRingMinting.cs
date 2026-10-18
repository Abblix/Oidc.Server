// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Writes the keys due on the rotation grid that the store does not hold yet.
/// </summary>
/// <param name="sealing">Seals a key before it is stored.</param>
/// <param name="policy">The roles a key is minted for.</param>
/// <param name="schedule">The rotation grid, and the clock a key's creation is read from.</param>
internal sealed class KeyRingMinting(KeyRingSealing sealing, MintedKeys policy, KeyRingSchedule schedule)
{
    /// <summary>
    /// Mints the keys the current period lacks, and reports whether it claimed any, whether this pod's claim won
    /// or another's did.
    /// </summary>
    public async Task<bool> MintDueKeysAsync(
        IReadOnlyList<StoredKey> entries,
        IKeyRingStore source,
        CancellationToken cancellationToken)
    {
        var claimed = false;

        foreach (var (usage, algorithm) in KeyRole.Of(policy))
        {
            var id = PeriodId(usage, algorithm);
            if (entries.Any(entry => entry.Id == id))
                continue;

            var jwe = await sealing.SealNewKeyAsync(usage, algorithm, cancellationToken);

            // Minted now, not at the start of the period. The period is a coordinate on the rotation grid and can
            // lie weeks in the past; dating the key by it would make it born already old, so the propagation
            // window would be long spent and it would start signing before any client could have fetched it.
            var entry = new StoredKey { Id = id, Jwe = jwe, CreatedAt = schedule.Now };

            // False means another pod claimed this period first. Its key is as good as ours, and the ring must
            // hold exactly one, so the loser simply drops what it generated. Nothing is retried.
            _ = await source.TryAddAsync(entry, cancellationToken);
            claimed = true;
        }

        return claimed;
    }

    /// <summary>
    /// The id every pod computes identically for the current period, which is what makes exactly one insert win.
    /// </summary>
    /// <remarks>
    /// It is built from the period on the rotation grid rather than from the clock, which is the whole point: two
    /// pods minting seconds apart still compute one id and race for it, instead of each creating a key. When a key
    /// was actually minted is recorded separately, since the period may have begun long before the pod got to it.
    /// </remarks>
    private string PeriodId(string usage, string algorithm)
        => $"{usage}-{algorithm}-{schedule.CurrentPeriodStart:yyyyMMddTHHmmssZ}";
}
