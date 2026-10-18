// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Opens the ring's stored entries under the custodian's key-encryption key: the step of a refresh that touches the
/// custodian once per key.
/// </summary>
/// <param name="keyEncryptionKeys">The key-encryption key versions an entry may have been sealed under.</param>
/// <param name="envelope">Opens a key from its stored form.</param>
internal sealed class KeyRingOpening(KeyEncryptionKeys keyEncryptionKeys, KeyEnvelope envelope)
{
    /// <summary>
    /// Opens every stored entry under the key-encryption key's versions, read once for the whole set.
    /// </summary>
    public async Task<IReadOnlyList<OpenedKey>> OpenAllAsync(
        IReadOnlyList<StoredKey> entries,
        CancellationToken cancellationToken)
    {
        var versions = await keyEncryptionKeys.VersionsAsync(cancellationToken)
            .ToArrayAsync(cancellationToken: cancellationToken);

        var opened = new List<OpenedKey>(entries.Count);
        foreach (var entry in entries)
        {
            var key = await envelope.OpenAsync(entry.Jwe, versions.ToAsyncEnumerable(), cancellationToken);
            opened.Add(new OpenedKey(entry.Id, key, entry.CreatedAt));
        }

        return opened;
    }
}
