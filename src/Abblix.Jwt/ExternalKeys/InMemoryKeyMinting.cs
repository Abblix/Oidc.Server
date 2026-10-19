// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Decides which keys the in-memory ring mints, and mints them.
/// </summary>
/// <param name="policy">What to mint and how often.</param>
internal sealed class InMemoryKeyMinting(LocalKeys policy)
{
    /// <summary>
    /// A new key for every role whose newest key among <paramref name="keys"/> has served longer than the rotation
    /// period at <paramref name="now"/>, or that has none.
    /// </summary>
    public IEnumerable<InMemoryMintedKey> Due(IEnumerable<InMemoryMintedKey> keys, DateTimeOffset now)
    {
        foreach (var (usage, algorithm) in Roles())
        {
            var newest = keys
                .Where(minted => minted.Key.Usage == usage)
                .Max(minted => (DateTimeOffset?)minted.CreatedAt);

            if (newest is { } mintedAt && now - mintedAt < policy.RotateEvery)
                continue;

            yield return new InMemoryMintedKey(JsonWebKeyFactory.CreateRsa(usage, algorithm, policy.RsaKeySize), now);
        }
    }

    /// <summary>The roles this ring mints for, and the algorithm each uses.</summary>
    private IEnumerable<(string Usage, string Algorithm)> Roles()
    {
        yield return (PublicKeyUsages.Signature, policy.SigningAlgorithm);

        if (policy.EncryptionAlgorithm is { } encryptionAlgorithm)
            yield return (PublicKeyUsages.Encryption, encryptionAlgorithm);
    }
}
