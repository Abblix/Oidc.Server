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
internal sealed class InMemoryKeyMinting
{
    private readonly LocalKeys _policy;

    /// <summary>
    /// Takes the policy the ring rotates on.
    /// </summary>
    /// <param name="policy">What to mint, how often, and how long to keep a retired key.</param>
    /// <exception cref="ArgumentOutOfRangeException">The policy rotates every instant or sooner, or retires a key
    /// before it stops producing.</exception>
    public InMemoryKeyMinting(LocalKeys policy)
    {
        EnsureRotatable(policy);
        _policy = policy;
    }

    /// <summary>
    /// Refuses a policy the ring cannot rotate on without leaving a role with no key.
    /// </summary>
    /// <param name="policy">What to mint, how often, and how long to keep a retired key.</param>
    /// <exception cref="ArgumentOutOfRangeException">The policy rotates every instant or sooner, or retires a key
    /// before it stops producing.</exception>
    public static void EnsureRotatable(LocalKeys policy)
    {
        // Each rotation mints before it retires, at one moment, so a role's newest key is younger than one rotation
        // period when retirement looks at it. Both bounds keep it there, and so keep every role with a key.
        if (policy.RotateEvery <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(policy),
                policy.RotateEvery,
                $"{nameof(LocalKeys.RotateEvery)} must be positive.");
        }

        if (policy.KeepRetiredFor < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(policy),
                policy.KeepRetiredFor,
                $"{nameof(LocalKeys.KeepRetiredFor)} must not be negative.");
        }
    }

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

            if (newest is { } mintedAt && now - mintedAt < _policy.RotateEvery)
                continue;

            yield return new InMemoryMintedKey(
                JsonWebKeyFactory.CreateRsa(usage, algorithm, _policy.RsaKeySize),
                now);
        }
    }

    /// <summary>The roles this ring mints for, and the algorithm each uses.</summary>
    private IEnumerable<(string Usage, string Algorithm)> Roles()
    {
        yield return (PublicKeyUsages.Signature, _policy.SigningAlgorithm);

        if (_policy.EncryptionAlgorithm is { } encryptionAlgorithm)
            yield return (PublicKeyUsages.Encryption, encryptionAlgorithm);
    }
}
