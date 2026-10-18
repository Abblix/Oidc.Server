// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// One refresh of a ring (Pipeline): adopt, mint, read again, open, retire, in that order. It holds no
/// partition of its own, so one serves every ring of a policy.
/// </summary>
/// <param name="adoption">Seeds a ring that has minted nothing yet with the keys a host hands over.</param>
/// <param name="minting">Writes the keys due on the rotation grid.</param>
/// <param name="opening">Opens the stored entries.</param>
/// <param name="schedule">The clock and the periods a retired key is kept by.</param>
internal sealed class KeyRingRefresh(
    KeyRingAdoption adoption,
    KeyRingMinting minting,
    KeyRingOpening opening,
    KeyRingSchedule schedule)
{
    private readonly KeyRingRetirement _retirement = new(schedule);

    /// <summary>Refreshes from <paramref name="source"/> and returns the opened keys the ring is to hold.</summary>
    /// <param name="source">Where the entries are read from and written to.</param>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    public async Task<IReadOnlyList<OpenedKey>> RunAsync(IKeyRingStore source, CancellationToken cancellationToken)
    {
        var entries = await source.LoadAsync(cancellationToken);

        // Adoption first, and in the same refresh as the first mint: the adopted key is dated a period back, so
        // the key minted below trails it rather than taking over the instant it appears.
        var adopted = await adoption.AdoptExistingKeysAsync(entries, source, cancellationToken);

        if (await minting.MintDueKeysAsync(entries, source, cancellationToken) || adopted)
        {
            // Something was written, by this pod or by another that won the race: re-read so the ring holds the
            // winner's key rather than the one generated here.
            entries = await source.LoadAsync(cancellationToken);
        }

        var opened = await opening.OpenAllAsync(entries, cancellationToken);
        return await _retirement.RetireExpiredAsync(opened, source, cancellationToken);
    }
}
