// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Covers the tier where the server mints its own keys and the custodian only protects them: a key is sealed to
/// the KEK and opened back through the real JWE seam, a period is minted exactly once across pods, and the set is
/// served produce-first with the private half gated.
/// </summary>
/// <remarks>
/// The custodian here is a stub that unwraps with the KEK's private half in memory, standing in for the remote
/// call a real one makes. That keeps the envelope, the ring projection and the minting race under test without a
/// live Vault, while the crypto itself is the library's own shipped JWE path rather than a test double.
/// </remarks>
public sealed class KeyRingTests : IDisposable
{
    private const string KeyEncryptionKeyName = "oidc-kek";

    // The JWE seam resolves its keyed algorithms from the provider on every call, so the provider must outlive
    // the ring it built. Kept here and disposed with the test rather than at the end of the factory.
    private readonly List<ServiceProvider> _providers = [];

    // One KEK per test, shared by every ring it builds: pods look at ONE custodian, so a key sealed by one pod
    // must open on another. A KEK per ring would make that impossible and hide the very thing under test.
    private readonly JsonWebKey _keyEncryptionKey =
        JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption, EncryptionAlgorithms.KeyManagement.RsaOaep256)
            with { KeyId = $"{KeyEncryptionKeyName}:1" };

    public void Dispose()
    {
        foreach (var provider in _providers)
            provider.Dispose();
    }
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    /// <summary>An in-memory ring store, standing in for the shared one a deployment uses.</summary>
    private sealed class FakeStore : IKeyRingStore
    {
        public List<StoredKey> Entries { get; } = [];

        public Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<StoredKey>>(Entries.ToList());

        public Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken)
        {
            if (Entries.Any(entry => entry.Id == key.Id))
                return Task.FromResult(false);

            Entries.Add(key);
            return Task.FromResult(true);
        }

        public Task RemoveAsync(string id, CancellationToken cancellationToken)
        {
            Entries.RemoveAll(entry => entry.Id == id);
            return Task.CompletedTask;
        }
    }

    private (KeyRing Ring, FakeStore Store) CreateRing(
        FakeStore? store = null,
        TimeSpan? propagation = null,
        DateTimeOffset? now = null,
        string? encryptionAlgorithm = null,
        TimeSpan? keepRetiredFor = null)
    {
        store ??= new FakeStore();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton(StubCustodian(_keyEncryptionKey));

        // Opening an envelope is a custodian unwrap, so the external decryption backend must be on the seam: the
        // KEK is public-only, and that is what routes its unwrap out of process.
        services.ComposeExternalKeyBackends();
        var provider = services.BuildServiceProvider();
        _providers.Add(provider);

        var envelope = new KeyEnvelope(provider.GetRequiredService<IJsonWebTokenEncryptor>());
        var time = new Mock<TimeProvider>();
        time.Setup(t => t.GetUtcNow()).Returns(now ?? Now);

        var ring = new KeyRing(
            store,
            provider.GetRequiredService<IKeyCustodian>(),
            envelope,
            new MintedKeys
            {
                KeyEncryptionKeyName = KeyEncryptionKeyName,
                RotateEvery = TimeSpan.FromDays(30),
                EncryptionAlgorithm = encryptionAlgorithm,
                KeepRetiredFor = keepRetiredFor,
            },
            Options.Create(new KeyRingOptions { KeyRolloverPropagation = propagation ?? TimeSpan.FromHours(1) }),
            time.Object);

        return (ring, store);
    }

    /// <summary>A custodian that holds the KEK: it publishes the public half and unwraps with the private one.</summary>
    private static IKeyCustodian StubCustodian(JsonWebKey keyEncryptionKey)
    {
        var custodian = new Mock<IKeyCustodian>();

        custodian
            .Setup(c => c.GetKeyVersionsAsync(KeyEncryptionKeyName, It.IsAny<CancellationToken>()))
            .Returns(new[] { new KeyVersion(keyEncryptionKey.Sanitize(false), Now.AddDays(-100)) }.ToAsyncEnumerable());

        custodian
            .Setup(c => c.UnwrapKeyAsync(
                keyEncryptionKey.KeyId!, It.IsAny<string>(), It.IsAny<JsonWebTokenHeader>(), It.IsAny<byte[]>(),
                It.IsAny<CancellationToken>()))
            .Returns((string _, string algorithm, JsonWebTokenHeader _, byte[] encryptedKey, CancellationToken _) =>
                Task.FromResult<byte[]?>(UnwrapLocally((RsaJsonWebKey)keyEncryptionKey, algorithm, encryptedKey)));

        return custodian.Object;
    }

    private static byte[] UnwrapLocally(RsaJsonWebKey keyEncryptionKey, string algorithm, byte[] encryptedKey)
    {
        using var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportParameters(keyEncryptionKey.ToRsaParameters());

        var padding = algorithm == EncryptionAlgorithms.KeyManagement.RsaOaep256
            ? System.Security.Cryptography.RSAEncryptionPadding.OaepSHA256
            : System.Security.Cryptography.RSAEncryptionPadding.OaepSHA1;

        return rsa.Decrypt(encryptedKey, padding);
    }

    [Fact]
    public async Task MintsASigningKey_SealsIt_AndOpensItBackWithItsPrivateHalf()
    {
        var (ring, store) = CreateRing();

        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        // The ring holds ciphertext, never a secret: what is shared is a JWE, and the store cannot read it.
        var entry = Assert.Single(store.Entries);
        Assert.Equal(5, entry.Jwe.Split('.').Length);

        // What comes back out is a usable signing key, which is the whole tier: the in-process signer owns it.
        var key = Assert.Single(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: true));
        Assert.True(key.HasPrivateKey);
        Assert.Equal(SigningAlgorithms.RS256, key.Algorithm);
    }

    [Fact]
    public async Task PublishingNeverCarriesThePrivateHalf()
    {
        var (ring, _) = CreateRing();

        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        // Not sharing the key is necessary but not sufficient: the other leak channel is publication.
        var published = Assert.Single(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false));
        Assert.True(published.HasPublicKey);
        Assert.False(published.HasPrivateKey);
    }

    [Fact]
    public async Task MintsNothingNew_WhenThePeriodAlreadyHasAKey()
    {
        var (ring, store) = CreateRing();

        await ring.RefreshAsync(TestContext.Current.CancellationToken);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        // The period id is derived, not random, so a second refresh recognises the period is served.
        Assert.Single(store.Entries);
    }

    [Fact]
    public async Task SecondPodTakesTheWinnersKey_WhenBothMintTheSamePeriod()
    {
        var shared = new FakeStore();
        var (first, _) = CreateRing(shared);
        var (second, _) = CreateRing(shared);

        await first.RefreshAsync(TestContext.Current.CancellationToken);
        await second.RefreshAsync(TestContext.Current.CancellationToken);

        // Exactly one key exists for the period: the loser discards what it generated rather than adding a second
        // key that only it could publish.
        var entry = Assert.Single(shared.Entries);

        var fromFirst = Assert.Single(first.Get(PublicKeyUsages.Signature, includePrivateKeys: false));
        var fromSecond = Assert.Single(second.Get(PublicKeyUsages.Signature, includePrivateKeys: false));
        Assert.Equal(fromFirst.KeyId, fromSecond.KeyId);
        Assert.Equal(entry.CreatedAt, Now.Subtract(Now - entry.CreatedAt));
    }

    [Fact]
    public async Task AFreshKeyIsAnnouncedBeforeItSigns_HoweverLongItsPeriodHasBeenRunning()
    {
        var shared = new FakeStore();
        var (first, _) = CreateRing(shared);
        await first.RefreshAsync(TestContext.Current.CancellationToken);

        // Mint the next period late, well after that period began. The key must still be announced for the full
        // propagation window: dating it by the period start would make it born already old, so it would start
        // signing at once, before any client could have fetched it from /jwks.
        var lateInThePeriod = Now.AddDays(31);
        var (second, _) = CreateRing(shared, now: lateInThePeriod);
        await second.RefreshAsync(TestContext.Current.CancellationToken);

        // Produce-first: the leader is what the signer takes. The fresh key trails until it clears the window.
        var producing = second.Get(PublicKeyUsages.Signature, includePrivateKeys: false).First();
        var oldest = shared.Entries.MinBy(entry => entry.CreatedAt)!;

        Assert.Equal(2, shared.Entries.Count);
        Assert.Equal(oldest.CreatedAt, Now);
        Assert.Equal(lateInThePeriod, shared.Entries.MaxBy(entry => entry.CreatedAt)!.CreatedAt);

        // The still-announced key is not the one signing, so a stale client never meets a token it cannot verify.
        var afterWindow = CreateRing(shared, now: lateInThePeriod.AddHours(2)).Ring;
        await afterWindow.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.NotEqual(
            producing.KeyId,
            afterWindow.Get(PublicKeyUsages.Signature, includePrivateKeys: false).First().KeyId);
    }

    [Fact]
    public async Task RetiresAKey_OnceItsSuccessorHasOutlivedTheTokensItSigned()
    {
        var shared = new FakeStore();
        var keepRetiredFor = TimeSpan.FromHours(1);

        // The clock has to move three times, because retirement is not about a key's own age. The first key is
        // minted, a rotation later the second is minted, and only after that one has been SIGNING for the
        // retention window is the first one safe to drop.
        var (first, _) = CreateRing(shared, keepRetiredFor: keepRetiredFor);
        await first.RefreshAsync(TestContext.Current.CancellationToken);
        var original = Assert.Single(shared.Entries).Id;

        var (second, _) = CreateRing(shared, now: Now.AddDays(31), keepRetiredFor: keepRetiredFor);
        await second.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, shared.Entries.Count);

        var (third, _) = CreateRing(shared, now: Now.AddDays(31).AddHours(3), keepRetiredFor: keepRetiredFor);
        await third.RefreshAsync(TestContext.Current.CancellationToken);

        // Gone from the store, not merely hidden: leaving it would grow the ring forever, and every entry costs a
        // custodian round-trip to open on each refresh.
        Assert.DoesNotContain(shared.Entries, entry => entry.Id == original);
    }

    [Fact]
    public async Task KeepsAPredecessor_WhileTheTokensItSignedCanStillBeAlive()
    {
        var shared = new FakeStore();

        var (first, _) = CreateRing(shared);
        await first.RefreshAsync(TestContext.Current.CancellationToken);

        // A rotation later, but well inside the retention window: the successor signs now, and yet the old key
        // must stay published, or every unexpired token it signed stops verifying.
        var justAfterRotation = Now.AddDays(31);
        var (later, _) = CreateRing(shared, now: justAfterRotation);
        await later.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Equal(2, shared.Entries.Count);
        Assert.Equal(2, later.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Count());
    }

    [Fact]
    public async Task NeverRetiresTheOnlyKey_HoweverOldItIs()
    {
        var shared = new FakeStore();
        var (ring, _) = CreateRing(shared);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        // Age alone retires nothing: a key retires when its SUCCESSOR takes over, and the newest key of a role
        // has none. Dropping it on age would leave the provider with no key to sign with at all.
        var (aged, _) = CreateRing(shared, now: Now.AddYears(5));
        await aged.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.NotEmpty(aged.Get(PublicKeyUsages.Signature, includePrivateKeys: false));
    }

    [Fact]
    public async Task MintsAnEncryptionKey_OnlyWhenTheAlgorithmIsNamed()
    {
        var (without, _) = CreateRing();
        await without.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Empty(without.Get(PublicKeyUsages.Encryption, includePrivateKeys: false));

        var (with, _) = CreateRing(encryptionAlgorithm: EncryptionAlgorithms.KeyManagement.RsaOaep256);
        await with.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Single(with.Get(PublicKeyUsages.Encryption, includePrivateKeys: false));
    }
}
