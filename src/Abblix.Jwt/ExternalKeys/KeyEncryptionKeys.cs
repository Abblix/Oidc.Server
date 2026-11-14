// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The custodian's key-encryption key a ring seals its keys to: its newest version, and every version an envelope
/// may have been sealed under.
/// </summary>
/// <param name="custodian">Holds the key-encryption key.</param>
/// <param name="policy">Names the key-encryption key.</param>
internal sealed class KeyEncryptionKeys(IKeyCustodian custodian, MintedKeys policy)
{
    /// <summary>
    /// The KEK version to seal with: the newest one. A KEK needs no propagation window, unlike a signing key,
    /// because it has no external consumer waiting to learn it - every reader of an envelope is this server.
    /// </summary>
    public async Task<JsonWebKey> NewestAsync(CancellationToken cancellationToken)
    {
        var versions = await custodian
            .GetKeyVersionsAsync(policy.KeyEncryptionKeyName, cancellationToken)
            .ToListAsync(cancellationToken);

        if (versions.Count == 0)
        {
            throw new InvalidOperationException(
                $"The custodian holds no key named '{policy.KeyEncryptionKeyName}', so nothing can seal a minted key.");
        }

        var newest = versions.MaxBy(version => version.CreatedAt).PublicKey;
        if (!newest.HasPublicKey)
        {
            throw new InvalidOperationException(
                $"The key-encryption key '{policy.KeyEncryptionKeyName}' must be asymmetric: sealing uses its " +
                "public half in process, and a symmetric key has none.");
        }

        return newest;
    }

    /// <summary>
    /// The key-encryption key's versions, public half only, which is what routes an unwrap to the custodian.
    /// </summary>
    public IAsyncEnumerable<JsonWebKey> VersionsAsync(CancellationToken cancellationToken)
        => custodian
            .GetKeyVersionsAsync(policy.KeyEncryptionKeyName, cancellationToken)
            .Select(version => version.PublicKey);
}
