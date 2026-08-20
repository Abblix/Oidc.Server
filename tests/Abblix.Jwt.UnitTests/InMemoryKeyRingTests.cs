// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for <see cref="InMemoryKeyRing"/>, the ring a host gets when it has no HSM or KMS.
/// </summary>
public class InMemoryKeyRingTests
{
    private static readonly LocalKeys Policy = new()
    {
        RotateEvery = TimeSpan.FromDays(30),
        KeepRetiredFor = TimeSpan.FromDays(7),

        // The smallest RSA size the platform will generate. These tests care about which keys are offered and
        // in what order, never about the strength of one, and a larger modulus only costs seconds per mint.
        RsaKeySize = 512,
    };

    private static InMemoryKeyRing CreateRing(TimeProvider timeProvider, LocalKeys? policy = null)
        => new(
            policy ?? Policy,
            Options.Create(new KeyRingOptions { KeyRolloverPropagation = TimeSpan.Zero }),
            timeProvider);

    /// <summary>
    /// A ring asked before anything has refreshed it still answers with a key, rather than an empty set that
    /// would read as "this provider signs with nothing".
    /// </summary>
    [Fact]
    public void MintsOnFirstUse()
    {
        var ring = CreateRing(new FakeTimeProvider());

        var keys = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: true);

        Assert.Single(keys);
    }

    /// <summary>
    /// Nothing is minted for a role the policy did not ask for.
    /// </summary>
    [Fact]
    public void MintsOnlyTheRolesThePolicyNames()
    {
        var ring = CreateRing(new FakeTimeProvider());

        Assert.Empty(ring.Get(PublicKeyUsages.Encryption, includePrivateKeys: false));
        Assert.Single(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false));
    }

    /// <summary>
    /// An encryption key is minted when the policy names an algorithm for it.
    /// </summary>
    [Fact]
    public void MintsAnEncryptionKeyWhenAsked()
    {
        var ring = CreateRing(
            new FakeTimeProvider(),
            Policy with { EncryptionAlgorithm = EncryptionAlgorithms.KeyManagement.RsaOaep });

        Assert.Single(ring.Get(PublicKeyUsages.Encryption, includePrivateKeys: false));
    }

    /// <summary>
    /// Asking twice within the rotation period returns the same key rather than minting a fresh one each time.
    /// </summary>
    [Fact]
    public void DoesNotMintOnEveryCall()
    {
        var ring = CreateRing(new FakeTimeProvider());

        var first = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single();
        var second = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single();

        Assert.Equal(first.KeyId, second.KeyId);
    }

    /// <summary>
    /// Once the rotation period has passed a fresh key leads, and the previous one is still offered. That
    /// second half is the point of a ring: retire the old key immediately and everything it signed stops
    /// verifying while its holders still believe it valid.
    /// </summary>
    [Fact]
    public void RotatesWithoutDroppingTheRetiredKey()
    {
        var timeProvider = new FakeTimeProvider();
        var ring = CreateRing(timeProvider);

        var original = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single();
        timeProvider.Advance(TimeSpan.FromDays(31));

        var keys = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).ToList();

        Assert.Equal(2, keys.Count);
        Assert.NotEqual(original.KeyId, keys[0].KeyId);
        Assert.Contains(keys, key => key.KeyId == original.KeyId);
    }

    /// <summary>
    /// A key is dropped once it has been retired longer than anything it produced can still be in use for.
    /// </summary>
    [Fact]
    public void DropsAKeyOnceNothingItProducedCanRemain()
    {
        var timeProvider = new FakeTimeProvider();
        var ring = CreateRing(timeProvider);

        var original = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single();

        // Past the rotation period and past the retention window that follows it.
        timeProvider.Advance(TimeSpan.FromDays(38));

        var keys = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).ToList();

        Assert.DoesNotContain(keys, key => key.KeyId == original.KeyId);
        Assert.NotEmpty(keys);
    }

    /// <summary>
    /// A role always keeps its newest key, however long the process has run without a refresh. Dropping it
    /// would leave the role with nothing to produce with, which is worse than serving one past its date.
    /// </summary>
    [Fact]
    public void NeverLeavesARoleWithNoKey()
    {
        var timeProvider = new FakeTimeProvider();
        var ring = CreateRing(timeProvider);

        ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false);
        timeProvider.Advance(TimeSpan.FromDays(3650));

        Assert.NotEmpty(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false));
    }

    /// <summary>
    /// Publication never carries the private half; signing does.
    /// </summary>
    [Fact]
    public void HandsOverThePrivateHalfOnlyWhenAsked()
    {
        var ring = CreateRing(new FakeTimeProvider());

        Assert.True(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: true).Single().HasPrivateKey);
        Assert.False(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single().HasPrivateKey);
    }

    /// <summary>
    /// Registering this ring alongside a key store is refused. A host that registered a store expects its keys
    /// shared between processes, and this ring shares nothing - so the mismatch is named at startup rather
    /// than discovered when a sign-in lands on the wrong replica.
    /// </summary>
    [Fact]
    public void RefusesToIgnoreAStoreTheHostRegistered()
    {
        var services = new ServiceCollection();
        services.AddSingleton(Mock.Of<IKeyRingStore>());

        var exception = Assert.Throws<InvalidOperationException>(() => services.AddInMemoryKeyRing(Policy));

        Assert.Contains(nameof(IKeyRingStore), exception.Message);
    }

    /// <summary>
    /// Without a store it registers, and what resolves is a ring.
    /// </summary>
    [Fact]
    public void RegistersWithoutAStore()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddOptions<KeyRingOptions>();

        services.AddInMemoryKeyRing(Policy);

        using var serviceProvider = services.BuildServiceProvider();
        Assert.IsType<InMemoryKeyRing>(serviceProvider.GetRequiredService<IKeyRing>());
    }
}
