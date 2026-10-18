// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// How the entries of adopted keys are named and dated, which is what tells them apart from minted ones and keeps
/// the order the host listed them in.
/// </summary>
internal static class AdoptedEntries
{
    /// <summary>What every adopted entry's id begins with, and no minted entry's does.</summary>
    private const string Prefix = "adopted-";

    /// <summary>Whether the entry <paramref name="id"/> names was adopted rather than minted.</summary>
    public static bool IsAdopted(string id) => id.StartsWith(Prefix, StringComparison.Ordinal);

    /// <summary>
    /// The id of the entry adopting each of <paramref name="keys"/>, in the same order, named after the key's
    /// thumbprint (RFC 7638) so every pod computes the same id for the same key.
    /// </summary>
    /// <exception cref="InvalidOperationException">A key has no private half, or lacks a member its thumbprint
    /// needs.</exception>
    public static string[] IdsFor(IReadOnlyList<JsonWebKey> keys)
    {
        var ids = new string[keys.Count];
        for (var index = 0; index < ids.Length; index++)
        {
            var key = keys[index];
            if (!key.HasPrivateKey)
            {
                throw new InvalidOperationException(
                    $"The key '{key.KeyId}' has no private half, so it cannot be adopted: an adopted key is the " +
                    "one that produces until the minted key's propagation window has passed, and producing needs " +
                    "the private half. Pass the key as it is loaded from its certificate or store.");
            }

            ids[index] = Prefix + key.ComputeJwkThumbprintBase64Url();
        }

        return ids;
    }

    /// <summary>
    /// The creation date of each key named in <paramref name="ids"/>, in the same order: each key is one second older
    /// than the one listed before it, so the ring signs with the first listed key rather than with whichever its
    /// store lists first. A second rather than a tick, because a store may keep times only to the millisecond.
    /// </summary>
    /// <param name="entries">The ring's entries, which may already hold part of the set.</param>
    /// <param name="ids">The entry ids of the set, in the order the host listed the keys.</param>
    /// <param name="firstWhenNoneWritten">The first key's date when no key of the set is written yet.</param>
    /// <remarks>
    /// A set completed by a later refresh is dated from an entry already written rather than from the clock, so the
    /// keys written later are not newer than the ones written first.
    /// </remarks>
    public static DateTimeOffset[] DatesFor(
        IReadOnlyList<StoredKey> entries,
        string[] ids,
        DateTimeOffset firstWhenNoneWritten)
    {
        var first = firstWhenNoneWritten;
        for (var index = 0; index < ids.Length; index++)
        {
            var written = entries.FirstOrDefault(entry => entry.Id == ids[index]);
            if (written is not null)
            {
                first = written.CreatedAt + TimeSpan.FromSeconds(index);
                break;
            }
        }

        var dates = new DateTimeOffset[ids.Length];
        for (var index = 0; index < dates.Length; index++)
            dates[index] = first - TimeSpan.FromSeconds(index);

        return dates;
    }
}
