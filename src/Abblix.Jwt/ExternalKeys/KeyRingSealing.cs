// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Seals the ring's keys to the custodian's key-encryption key, the form they are stored in.
/// </summary>
/// <param name="keyEncryptionKeys">The key-encryption key a key is sealed to.</param>
/// <param name="envelope">Seals a key into its stored form.</param>
/// <param name="policy">The algorithms a key is generated and sealed under.</param>
internal sealed class KeyRingSealing(KeyEncryptionKeys keyEncryptionKeys, KeyEnvelope envelope, MintedKeys policy)
{
    /// <summary>Generates a key for the role and seals it to the newest KEK version.</summary>
    public async Task<string> SealNewKeyAsync(string usage, string algorithm, CancellationToken cancellationToken)
    {
        var key = JsonWebKeyFactory.CreateRsa(usage, algorithm, policy.RsaKeySize);
        var keyEncryptionKey = await keyEncryptionKeys.NewestAsync(cancellationToken);

        return await SealAsync(key, keyEncryptionKey, cancellationToken);
    }

    /// <summary>Seals each key to the newest KEK version, read once for the whole set, in the order given.</summary>
    public async Task<IReadOnlyList<string>> SealAllAsync(
        IReadOnlyList<JsonWebKey> keys,
        CancellationToken cancellationToken)
    {
        var keyEncryptionKey = await keyEncryptionKeys.NewestAsync(cancellationToken);

        var sealedKeys = new List<string>(keys.Count);
        foreach (var key in keys)
            sealedKeys.Add(await SealAsync(key, keyEncryptionKey, cancellationToken));

        return sealedKeys;
    }

    /// <summary>Seals a key to the given KEK version, which is what the ring stores.</summary>
    private Task<string> SealAsync(JsonWebKey key, JsonWebKey keyEncryptionKey, CancellationToken cancellationToken)
        => envelope.SealAsync(
            key, keyEncryptionKey, policy.KeyWrapAlgorithm, policy.ContentEncryptionAlgorithm, cancellationToken);
}
