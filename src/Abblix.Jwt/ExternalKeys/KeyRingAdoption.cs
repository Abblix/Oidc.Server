// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Seeds an empty ring with the keys a host hands over, so the keys it already published keep producing until the
/// first minted key has reached every consumer.
/// </summary>
/// <param name="sealing">Seals the keys before they are stored.</param>
/// <param name="policy">The keys to adopt.</param>
/// <param name="schedule">The clock and the rotation period an adopted key is dated by.</param>
internal sealed class KeyRingAdoption(KeyRingSealing sealing, MintedKeys policy, KeyRingSchedule schedule)
{
    /// <summary>
    /// Takes the keys the server already signs with into an empty ring, and reports whether it claimed any, whether
    /// this pod's claim won or another's did.
    /// </summary>
    /// <remarks>
    /// Only into an EMPTY ring, which is what lets the call stay in a host's registration forever: the moment the
    /// ring holds anything, adoption is over. A key that has since retired is therefore not brought back, and the
    /// ring cannot empty itself to make it look otherwise - the newest key serving a role never retires.
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
        if (entries.Count > 0 || policy.AdoptedKeys.Count == 0)
            return false;

        // Dated one rotation period back, which is what makes it the active key: the key minted in this same
        // refresh is younger than the propagation window, so it is published and verifiable while this one keeps
        // producing, and it takes over once the window has passed.
        var createdAt = schedule.Now - schedule.RotateEvery;

        // Every key is checked before the custodian is asked or anything is stored, so a refused set leaves the
        // ring empty rather than holding the keys listed before the refused one
        foreach (var key in policy.AdoptedKeys)
        {
            if (!key.HasPrivateKey)
            {
                throw new InvalidOperationException(
                    $"The key '{key.KeyId}' has no private half, so it cannot be adopted: an adopted key is the " +
                    "one that produces until the minted key's propagation window has passed, and producing needs " +
                    "the private half. Pass the key as it is loaded from its certificate or store.");
            }
        }

        var sealedKeys = await sealing.SealAllAsync(policy.AdoptedKeys, cancellationToken);
        for (var index = 0; index < sealedKeys.Count; index++)
        {
            var entry = new StoredKey
            {
                Id = $"adopted-{policy.AdoptedKeys[index].ComputeJwkThumbprintBase64Url()}",
                Jwe = sealedKeys[index],
                CreatedAt = createdAt,
            };

            _ = await source.TryAddAsync(entry, cancellationToken);
        }

        return true;
    }
}
