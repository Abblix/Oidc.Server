// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ExternalKeys;
using Xunit;

namespace Abblix.Jwt.UnitTests;

// How several adopted keys of one role are ordered and retired: which of them signs, and how long each stays
// published
public sealed partial class KeyRingTests
{
    private static JsonWebKey AdoptableSigningKey(string keyId)
        => JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256) with { KeyId = keyId };

    private static IEnumerable<string?> Published(KeyRing ring, string usage)
        => ring.Get(usage, includePrivateKeys: false).Select(key => key.KeyId);

    /// <summary>
    /// Adopted keys of one role are not each other's successors: every one stays published until the first
    /// minted key of its role has signed for the retention window, so the tokens each of them signed keep
    /// verifying until they expire.
    /// </summary>
    [Fact]
    public async Task SeveralAdoptedKeysOfOneRole_StayPublished_UntilTheMintedKeyHasServedTheRetention()
    {
        var store = new FakeStore();
        var propagation = TimeSpan.FromHours(1);
        var adopted = new[] { AdoptableSigningKey("first"), AdoptableSigningKey("second"), AdoptableSigningKey("third") };
        var (adopting, _) = CreateRing(store, propagation: propagation, adoptedKeys: adopted);
        await adopting.RefreshAsync(TestContext.Current.CancellationToken);

        // The minted key has taken over; every adopted key is still within the retention window
        var (afterTakeover, _) = CreateRing(store, propagation: propagation, now: Now + propagation + TimeSpan.FromMinutes(1));
        await afterTakeover.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal(["first", "second", "third"], Published(afterTakeover, PublicKeyUsages.Signature).Skip(1).Order());

        // The minted key has signed for one rotation period, the default retention, past its propagation window
        var (afterRetention, _) = CreateRing(
            store, propagation: propagation, now: Now + propagation + TimeSpan.FromDays(30) + TimeSpan.FromMinutes(1));
        await afterRetention.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.DoesNotContain(Published(afterRetention, PublicKeyUsages.Signature), id => id is "first" or "second" or "third");
    }

    /// <summary>
    /// A retention shorter than a rotation period does not remove an adopted key in the very refresh that adopts
    /// it: its retention is counted from the minted key that replaces it, not from the other adopted keys.
    /// </summary>
    [Fact]
    public async Task AShortRetention_KeepsEveryAdoptedKey_ThroughTheAdoptingRefresh()
    {
        var (ring, _) = CreateRing(
            keepRetiredFor: TimeSpan.FromHours(1),
            adoptedKeys: [AdoptableSigningKey("first"), AdoptableSigningKey("second")]);

        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        var published = Published(ring, PublicKeyUsages.Signature).ToList();
        Assert.Equal("first", published[0]);
        Assert.Contains("second", published);
    }

    /// <summary>
    /// A role nobody mints for keeps its adopted keys: no minted key ever takes over from them, so none of them
    /// may be counted as replaced.
    /// </summary>
    [Fact]
    public async Task AdoptedKeysOfARoleNobodyMintsFor_NeverRetire()
    {
        var store = new FakeStore();
        var encryptionKeys = new[]
        {
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256)
                with { KeyId = "enc-first" },
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256)
                with { KeyId = "enc-second" },
        };
        var (adopting, _) = CreateRing(store, adoptedKeys: encryptionKeys);
        await adopting.RefreshAsync(TestContext.Current.CancellationToken);

        var (later, _) = CreateRing(store, now: Now + TimeSpan.FromDays(90));
        await later.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Equal(["enc-first", "enc-second"], Published(later, PublicKeyUsages.Encryption).Order());
    }

    /// <summary>
    /// The ring signs with the first key the host listed, as it did before the move, whatever order its store
    /// lists the entries in.
    /// </summary>
    [Fact]
    public async Task TheFirstListedAdoptedKeySigns_WhateverOrderTheStoreListsIn()
    {
        var store = new FakeStore { ListsInReverse = true };
        var (ring, _) = CreateRing(store, adoptedKeys: [AdoptableSigningKey("first"), AdoptableSigningKey("second")]);

        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Equal("first", Published(ring, PublicKeyUsages.Signature).First());
    }

    /// <summary>
    /// A set completed by a later refresh keeps the host's order: the key written later is not newer than the one
    /// written first, so the first listed key still signs.
    /// </summary>
    [Fact]
    public async Task AnAdoptedSetCompletedLater_StillSignsWithTheFirstListedKey()
    {
        var store = new FakeStore { WritesBeforeFailure = 1 };
        var adopted = new[] { AdoptableSigningKey("first"), AdoptableSigningKey("second") };
        var (failing, _) = CreateRing(store, adoptedKeys: adopted);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => failing.RefreshAsync(TestContext.Current.CancellationToken));

        var (completing, _) = CreateRing(store, now: Now + TimeSpan.FromMinutes(10), adoptedKeys: adopted);
        await completing.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Equal("first", Published(completing, PublicKeyUsages.Signature).First());
    }
}
