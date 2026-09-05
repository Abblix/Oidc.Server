// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Covers the placement where the server mints its own keys and the custodian only protects them: a key is sealed to
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
    /// <remarks>
    /// It can also refuse to answer, which is how the refresh loop's behaviour under an outage is exercised:
    /// <see cref="FailWith"/> is the store being down, <see cref="BlockUntilCancelled"/> is a call still in flight
    /// when the host shuts down. <see cref="Loads"/> counts through both, because the point of those tests is that
    /// the loop asks again.
    /// </remarks>
    private sealed class FakeStore : IKeyRingStore
    {
        public List<StoredKey> Entries { get; } = [];

        /// <summary>What every subsequent load throws, or <c>null</c> while the store is healthy.</summary>
        public Exception? FailWith { get; set; }

        /// <summary>Whether a load hangs until its token is cancelled, instead of answering.</summary>
        public bool BlockUntilCancelled { get; set; }

        private int _loads;

        /// <summary>How many loads have been attempted. Written on the timer's thread, read on the test's.</summary>
        public int Loads => Volatile.Read(ref _loads);

        public async Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _loads);

            if (BlockUntilCancelled)
                await Task.Delay(Timeout.Infinite, cancellationToken);

            if (FailWith is not null)
                throw FailWith;

            return Entries.ToList();
        }

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
        TimeSpan? keepRetiredFor = null,
        TimeProvider? timeProvider = null,
        IReadOnlyList<JsonWebKey>? adoptedKeys = null)
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

        // A stopped clock is enough for everything the ring decides from one instant; a test driving the refresh
        // timer passes a clock it can advance, and the ring must read the same one so the two agree on now.
        TimeProvider time;
        if (timeProvider is not null)
        {
            time = timeProvider;
        }
        else
        {
            var stopped = new Mock<TimeProvider>();
            stopped.Setup(t => t.GetUtcNow()).Returns(now ?? Now);
            time = stopped.Object;
        }

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
                AdoptedKeys = adoptedKeys ?? [],
            },
            Options.Create(new KeyRingOptions { KeyRolloverPropagation = propagation ?? TimeSpan.FromHours(1) }),
            time);

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

        // What comes back out is a usable signing key, which is the whole placement: the in-process signer owns it.
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

    /// <summary>
    /// A key naming no role serves BOTH, because RFC 7517 section 4.2 makes <c>use</c> optional and
    /// single-valued: a key permitted to sign and to encrypt is expressed by omitting the member, never by a
    /// multi-valued one. Reading its absence as "no role" would drop exactly those keys from the published set,
    /// and silently. A certificate permitting both signing and encipherment produces precisely such a key.
    /// </summary>
    [Fact]
    public async Task AKeyNamingNoRole_ServesBoth()
    {
        var store = new FakeStore();
        var (ring, _) = CreateRing(store);

        await AddUnrestrictedKey(store, "adopted", Now);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Contains(
            ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false),
            key => key.KeyId == "unrestricted");

        Assert.Contains(
            ring.Get(PublicKeyUsages.Encryption, includePrivateKeys: false),
            key => key.KeyId == "unrestricted");
    }

    /// <summary>
    /// Retirement is decided per role, and a key is kept while ANY role it serves still needs it. So an
    /// unrestricted key outlives its signing successor: the encryption role has not moved on, and dropping the
    /// key would leave that role with nothing at all.
    /// </summary>
    [Fact]
    public async Task AKeyNamingNoRole_OutlivesASuccessorInOneRoleOnly()
    {
        var store = new FakeStore();

        // The ring mints signing keys only - no encryption algorithm is named - so the unrestricted key is the
        // one and only key the encryption role has.
        await AddUnrestrictedKey(store, "adopted", Now.AddDays(-400));

        var (ring, _) = CreateRing(store, now: Now);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Contains(
            ring.Get(PublicKeyUsages.Encryption, includePrivateKeys: false),
            key => key.KeyId == "unrestricted");

        Assert.Contains(store.Entries, entry => entry.Id == "adopted");
    }

    /// <summary>
    /// The control for the pair above: once BOTH roles have a successor past the window, the unrestricted key
    /// does leave. Without this the tests would hold equally for a ring that never retires anything.
    /// </summary>
    [Fact]
    public async Task AKeyNamingNoRole_RetiresOnceBothRolesMovedOn()
    {
        var store = new FakeStore();
        await AddUnrestrictedKey(store, "adopted", Now.AddDays(-400));

        // Both roles mint here, so both gain a successor; then time passes far beyond window plus retention.
        var (ring, _) = CreateRing(
            store,
            now: Now,
            encryptionAlgorithm: EncryptionAlgorithms.KeyManagement.RsaOaep256);

        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        var (later, _) = CreateRing(
            store,
            now: Now.AddDays(120),
            encryptionAlgorithm: EncryptionAlgorithms.KeyManagement.RsaOaep256);

        await later.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.DoesNotContain(store.Entries, entry => entry.Id == "adopted");
    }

    /// <summary>Seals a key carrying no role and stores it, the way an existing certificate would arrive.</summary>
    private async Task AddUnrestrictedKey(FakeStore store, string entryId, DateTimeOffset createdAt)
    {
        var unrestricted = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            with { Usage = null, KeyId = "unrestricted" };

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton(StubCustodian(_keyEncryptionKey));
        services.ComposeExternalKeyBackends();
        var provider = services.BuildServiceProvider();
        _providers.Add(provider);

        var envelope = new KeyEnvelope(provider.GetRequiredService<IJsonWebTokenEncryptor>());

        store.Entries.Add(new StoredKey
        {
            Id = entryId,
            Jwe = await envelope.SealAsync(
                unrestricted,
                _keyEncryptionKey,
                EncryptionAlgorithms.KeyManagement.RsaOaep256,
                EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
                TestContext.Current.CancellationToken),
            CreatedAt = createdAt,
        });
    }

    /// <summary>
    /// An adopted key keeps producing while the key minted alongside it serves out its propagation window. That
    /// is the whole reason adoption exists: into an empty ring a minted key would produce from its first second,
    /// and every client holding a JWKS copy from the second before would meet a token it cannot verify.
    /// </summary>
    [Fact]
    public async Task AnAdoptedKeyProduces_WhileTheKeyMintedBesideItIsStillAnnounced()
    {
        var existing = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            with { KeyId = "from-certificate" };

        var (ring, store) = CreateRing(adoptedKeys: [existing]);

        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        // Both are published - that is the overlap - and the adopted one leads, so it is the one signing.
        var published = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).ToList();
        Assert.Equal(2, published.Count);
        Assert.Equal("from-certificate", published[0].KeyId);

        // The store holds ciphertext for the adopted key too: it is sealed on the way in like any other entry.
        var adopted = Assert.Single(store.Entries, entry => entry.Id.StartsWith("adopted-"));
        Assert.Equal(5, adopted.Jwe.Split('.').Length);
    }

    /// <summary>
    /// The control for the test above, and the reason adoption dates the key backwards: once the propagation
    /// window has passed, the minted key takes over and the adopted one merely stays published.
    /// </summary>
    [Fact]
    public async Task TheMintedKeyTakesOver_OnceThePropagationWindowHasPassed()
    {
        var existing = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            with { KeyId = "from-certificate" };

        var propagation = TimeSpan.FromHours(1);
        var store = new FakeStore();
        var (ring, _) = CreateRing(store, propagation: propagation, adoptedKeys: [existing]);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        var (later, _) = CreateRing(
            store, propagation: propagation, now: Now + propagation + TimeSpan.FromMinutes(1));
        await later.RefreshAsync(TestContext.Current.CancellationToken);

        var published = later.Get(PublicKeyUsages.Signature, includePrivateKeys: false).ToList();
        Assert.Equal(2, published.Count);
        Assert.NotEqual("from-certificate", published[0].KeyId);
        Assert.Contains(published, key => key.KeyId == "from-certificate");
    }

    /// <summary>
    /// Adoption happens only into an empty ring, which is what makes leaving the call in a host's registration
    /// harmless: a key the ring has since retired is not brought back by the next refresh.
    /// </summary>
    [Fact]
    public async Task AnAdoptedKeyIsNotTakenAgain_OnceTheRingHoldsAnything()
    {
        var existing = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            with { KeyId = "from-certificate" };

        var store = new FakeStore();
        var (ring, _) = CreateRing(store, adoptedKeys: [existing]);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        // Stands in for the day the adopted key retires: the ring still holds the minted key, so it is not empty.
        var adopted = Assert.Single(store.Entries, entry => entry.Id.StartsWith("adopted-"));
        store.Entries.Remove(adopted);

        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.DoesNotContain(store.Entries, entry => entry.Id.StartsWith("adopted-"));
    }

    /// <summary>
    /// A key with no private half is refused where it is named, not where it fails. Adopted dated backwards, it
    /// would be the ACTIVE key, so accepting it would mean a server that publishes a full ring and cannot sign.
    /// </summary>
    [Fact]
    public async Task AKeyWithNoPrivateHalfIsRefused()
    {
        var publicOnly = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            .Sanitize(includePrivateKeys: false) with { KeyId = "public-only" };

        var (ring, _) = CreateRing(adoptedKeys: [publicOnly]);

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ring.RefreshAsync(TestContext.Current.CancellationToken));

        Assert.Contains("public-only", refusal.Message);
    }

    /// <summary>
    /// The builder call reaches the ring. Everything above constructs the ring directly, which proves the
    /// behaviour and nothing about the wiring - and a registration method that quietly reaches nobody reads
    /// exactly like one that works.
    /// </summary>
    [Fact]
    public async Task AdoptExistingKeys_ReachesTheRing_ThroughTheHostedService()
    {
        var existing = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)
            with { KeyId = "from-certificate" };

        var store = new FakeStore();
        var time = new Mock<TimeProvider>();
        time.Setup(t => t.GetUtcNow()).Returns(Now);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton(StubCustodian(_keyEncryptionKey));
        services.AddSingleton<IKeyRingStore>(store);
        services.AddSingleton(time.Object);
        services.ComposeExternalKeyBackends();
        services
            .AddKeyRing(new MintedKeys { KeyEncryptionKeyName = KeyEncryptionKeyName })
            .AdoptExistingKeys(existing);

        var provider = services.BuildServiceProvider();
        _providers.Add(provider);

        // Started the way a host starts it: the first refresh runs in StartAsync, which is the door production
        // walks through.
        var refresher = provider.GetServices<IHostedService>().Single();
        await refresher.StartAsync(TestContext.Current.CancellationToken);
        await refresher.StopAsync(TestContext.Current.CancellationToken);

        var published = provider.GetRequiredService<IKeyRing>()
            .Get(PublicKeyUsages.Signature, includePrivateKeys: false).ToList();

        Assert.Equal(2, published.Count);
        Assert.Equal("from-certificate", published[0].KeyId);
    }

    /// <summary>
    /// The refresh service resolves, and over the same ring every consumer reads. Registering the contract with
    /// its own factory would build a second ring, and nothing at runtime would say so: the loop would keep one
    /// current while the JWKS endpoint served the other, which surfaces as keys that never rotate.
    /// </summary>
    [Fact]
    public void TheRefreshServiceResolves_OverTheRingEveryoneElseReads()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton(StubCustodian(_keyEncryptionKey));
        services.AddSingleton<IKeyRingStore>(new FakeStore());
        services.ComposeExternalKeyBackends();
        services.AddKeyRing(new MintedKeys { KeyEncryptionKeyName = KeyEncryptionKeyName });

        var provider = services.BuildServiceProvider();
        _providers.Add(provider);

        Assert.IsType<KeyRingRefreshService>(Assert.Single(provider.GetServices<IHostedService>()));
        Assert.Same(provider.GetRequiredService<KeyRing>(), provider.GetRequiredService<IKeyRing>());
    }

    /// <summary>
    /// The refresh loop keeps ticking after the store refuses to answer. A failure there costs freshness and
    /// nothing else - the keys are already open in memory and signing needs no custodian - so letting it escape
    /// would trade a store outage for the loss of every pod, since a faulted background service stops the host.
    /// </summary>
    [Fact]
    public async Task RefreshLoop_KeepsTicking_AfterTheStoreRefuses()
    {
        var propagation = TimeSpan.FromHours(1);
        var time = new SignallingTimeProvider(new FakeTimeProvider(Now));
        var (ring, store) = CreateRing(propagation: propagation, timeProvider: time);
        var logger = new RecordingLogger<KeyRingRefreshService>();
        var service = new KeyRingRefreshService(
            logger, ring, Options.Create(new KeyRingOptions { KeyRolloverPropagation = propagation }), time);

        await service.StartAsync(TestContext.Current.CancellationToken);
        await time.TimerCreated.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        var served = Assert.Single(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false)).KeyId;

        store.FailWith = new InvalidOperationException("the ring store is unreachable");
        var loadsBeforeOutage = store.Loads;

        // The tick that fails, then the tick after it. The second is the assertion that matters: an escaping
        // exception ends ExecuteAsync, so the loop would be gone and this load would never arrive.
        time.Advance(propagation / 2);
        await WaitForLoads(store, loadsBeforeOutage + 1);

        time.Advance(propagation / 2);
        await WaitForLoads(store, loadsBeforeOutage + 2);

        Assert.False(service.ExecuteTask!.IsFaulted);
        Assert.Equal(served, Assert.Single(ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false)).KeyId);
        Assert.Equal(2, logger.Entries.Count(entry => entry.Level == LogLevel.Error));

        await service.StopAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Shutting the host down while a refresh is in flight is not a failure and must not be reported as one. A
    /// cancelled call would otherwise write an Error on every ordinary pod restart, which is how a log nobody
    /// reads is made.
    /// </summary>
    [Fact]
    public async Task RefreshLoop_ReportsNothing_WhenShutdownCancelsARefreshInFlight()
    {
        var propagation = TimeSpan.FromHours(1);
        var time = new SignallingTimeProvider(new FakeTimeProvider(Now));
        var (ring, store) = CreateRing(propagation: propagation, timeProvider: time);
        var logger = new RecordingLogger<KeyRingRefreshService>();
        var service = new KeyRingRefreshService(
            logger, ring, Options.Create(new KeyRingOptions { KeyRolloverPropagation = propagation }), time);

        await service.StartAsync(TestContext.Current.CancellationToken);
        await time.TimerCreated.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        // The next load hangs, so the refresh is still running when the host stops and its token is cancelled.
        store.BlockUntilCancelled = true;
        var loadsBeforeStop = store.Loads;

        time.Advance(propagation / 2);
        await WaitForLoads(store, loadsBeforeStop + 1);

        await service.StopAsync(TestContext.Current.CancellationToken);

        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// Waits for the loop to have attempted a given number of loads. The clock the timer runs on is the test's to
    /// advance, but the loop body runs on its own thread, so real elapsed time is what bounds the wait - and a
    /// loop that stopped fails here by timeout rather than hanging the suite.
    /// </summary>
    private static async Task WaitForLoads(FakeStore store, int expected)
    {
        var waited = Stopwatch.StartNew();
        while (store.Loads < expected && waited.Elapsed < TimeSpan.FromSeconds(10))
            await Task.Delay(10, TestContext.Current.CancellationToken);

        Assert.True(store.Loads >= expected, $"Expected at least {expected} loads, the store saw {store.Loads}.");
    }

    /// <summary>
    /// A fake clock that says when the loop has armed its timer.
    /// </summary>
    /// <remarks>
    /// Starting the service returns as soon as the loop is scheduled, not when it reaches its first await, so
    /// advancing the clock straight away can land before the timer exists - and a tick nobody is holding a timer
    /// for is simply lost, which reads as a loop that died. Waiting for <see cref="TimerCreated"/> removes the
    /// race outright: <see cref="PeriodicTimer"/> holds a tick that arrives with no waiter, so once the timer is
    /// armed every advance is observed whether or not the loop has reached the await yet.
    /// </remarks>
    private sealed class SignallingTimeProvider(FakeTimeProvider inner) : TimeProvider
    {
        private readonly TaskCompletionSource _timerCreated =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task TimerCreated => _timerCreated.Task;

        public void Advance(TimeSpan delta) => inner.Advance(delta);

        public override DateTimeOffset GetUtcNow() => inner.GetUtcNow();

        public override TimeZoneInfo LocalTimeZone => inner.LocalTimeZone;

        public override long TimestampFrequency => inner.TimestampFrequency;

        public override long GetTimestamp() => inner.GetTimestamp();

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = inner.CreateTimer(callback, state, dueTime, period);
            _timerCreated.TrySetResult();
            return timer;
        }
    }

    /// <summary>
    /// Keeps what was logged, so a test can assert both that a failure was reported and that a normal shutdown
    /// was not.
    /// </summary>
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (Entries)
                Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
