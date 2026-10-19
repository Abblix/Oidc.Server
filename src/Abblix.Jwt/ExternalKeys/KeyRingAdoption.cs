// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Seeds a ring that has minted nothing yet with the keys a host hands over, so the keys it already published keep
/// producing until the first minted key has reached every consumer.
/// </summary>
/// <param name="sealing">Seals the keys before they are stored.</param>
/// <param name="policy">The keys to adopt.</param>
/// <param name="schedule">The clock and the rotation period an adopted key is dated by.</param>
internal sealed class KeyRingAdoption(KeyRingSealing sealing, MintedKeys policy, KeyRingSchedule schedule)
{
    /// <summary>
    /// Takes the keys the server already signs with into a ring that has minted nothing yet, and reports whether it
    /// claimed any, whether this pod's claim won or another's did.
    /// </summary>
    /// <remarks>
    /// Only before the first minted key, which is what lets the call stay in a host's registration forever: the
    /// moment the ring holds a minted key, adoption is over. A key that has since retired is therefore not brought
    /// back, and the ring cannot lose its minted keys to make it look otherwise - the newest key serving a role never
    /// retires. Until then a refresh adopts the whole set again, so a set whose writing stopped partway, because the
    /// store failed or the pod died, is completed by the next refresh: the store keeps the entries already written
    /// and adds the rest, and the minting that would end adoption runs only after the set is written.
    /// <para>
    /// The entry is named after the key's own thumbprint (RFC 7638), so every pod computes the same id for the
    /// same key and the store's insert-if-absent settles the race exactly as it does for minting. The id also
    /// cannot collide with a period id, which is built from a role and an instant.
    /// </para>
    /// </remarks>
    public async Task<bool> AdoptExistingKeysAsync(
        IReadOnlyList<StoredKey> entries,
        IKeyRingStore source,
        CancellationToken cancellationToken)
    {
        if (policy.AdoptedKeys.Count == 0 || entries.Any(entry => !AdoptedEntries.IsAdopted(entry.Id)))
            return false;

        // Every key is checked, and named, before the custodian is asked or anything is stored, so a refused set
        // leaves the ring without the keys listed before the refused one
        var ids = AdoptedEntries.IdsFor(policy.AdoptedKeys);

        // Dated a rotation period before the current one, or at the earliest instant there is for a ring that
        // never rotates, which is what makes the first of them the active key:
        // the key minted in this same refresh is younger than the propagation window, so it is published and
        // verifiable while this one keeps producing, and it takes over once the window has passed. The date is
        // read off the rotation grid rather than the clock, so every pod adopting in one period dates the set alike.
        var dates = AdoptedEntries.DatesFor(entries, ids, schedule.PreviousPeriodStart);

        var sealedKeys = await sealing.SealAllAsync(policy.AdoptedKeys, cancellationToken);
        for (var index = 0; index < sealedKeys.Count; index++)
        {
            var entry = new StoredKey
            {
                Id = ids[index],
                Jwe = sealedKeys[index],
                CreatedAt = dates[index],
            };

            _ = await source.TryAddAsync(entry, cancellationToken);
        }

        return true;
    }
}
