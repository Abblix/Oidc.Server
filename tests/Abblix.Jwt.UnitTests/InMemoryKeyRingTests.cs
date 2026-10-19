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

        // These tests care about which keys are offered and in what order, never about the strength of
        // one. The floor is what the factory will mint, so a smaller size is refused where it is created
        // rather than at the first signature.
        RsaKeySize = KeySizeFloors.MinimumRsaKeyBits,
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
    /// The ring reports when its newest key for a role appeared, which is what tells a stopped rotation from a
    /// working one: a ring that has stopped keeps serving what it holds and looks healthy from every other angle.
    /// </summary>
    [Fact]
    public async Task ReportsWhenItsNewestKeyAppeared()
    {
        var time = new FakeTimeProvider();
        var ring = CreateRing(time);
        ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false);

        var minted = time.GetUtcNow();
        time.Advance(Policy.RotateEvery);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        // The rotation that just happened, not the one before it: an age read off the oldest key would keep
        // growing while rotation worked, and would say nothing when it stopped.
        Assert.Equal(minted + Policy.RotateEvery, ring.NewestKeyCreatedAt(PublicKeyUsages.Signature));
    }

    /// <summary>
    /// A role the ring holds nothing for has no such moment, which is not the same answer as an old one.
    /// </summary>
    [Fact]
    public void ReportsNothing_ForARoleItHoldsNoKeyFor()
    {
        var ring = CreateRing(new FakeTimeProvider());
        ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false);

        // The policy names no encryption algorithm, so the ring mints nothing for that role.
        Assert.Null(ring.NewestKeyCreatedAt(PublicKeyUsages.Encryption));
    }

    /// <summary>
    /// Asking how stale the ring is does not freshen it: a caller that only reads must not be the thing that
    /// mints, or a health check would report health it created itself.
    /// </summary>
    /// <remarks>
    /// Read off what the ring holds AFTERWARDS rather than off the answer, because a body that minted and then
    /// reported what it had before minting answers the same thing while doing the forbidden work. The clock moves
    /// in between, so the key the ring ends up with dates from the call that was allowed to mint.
    /// </remarks>
    [Fact]
    public void ReportingItsFreshness_MintsNothing()
    {
        var time = new FakeTimeProvider();
        var ring = CreateRing(time);

        Assert.Null(ring.NewestKeyCreatedAt(PublicKeyUsages.Signature));

        time.Advance(TimeSpan.FromDays(1));
        ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false);

        Assert.Equal(time.GetUtcNow(), ring.NewestKeyCreatedAt(PublicKeyUsages.Signature));
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

    /// <summary>
    /// Two requests arriving as a key is due both sign with the new one: the one that read the clock first and
    /// waited for the other to rotate does not choose its key as of a moment before the rotation it then sees.
    /// </summary>
    [Fact]
    public void RequestsDuringARotation_AllProduceWithTheNewKey()
    {
        var ct = TestContext.Current.CancellationToken;
        var moment = new AsyncLocal<DateTimeOffset?>();
        var holdNextRead = new AsyncLocal<bool>();
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var clock = new Mock<TimeProvider>();
        clock.Setup(time => time.GetUtcNow()).Returns(() =>
        {
            if (holdNextRead.Value)
            {
                holdNextRead.Value = false;
                held.Set();
                release.Wait(TimeSpan.FromSeconds(5), ct);
            }

            return moment.Value ?? DateTimeOffset.UnixEpoch;
        });

        var ring = CreateRing(clock.Object, Policy with { EncryptionAlgorithm = null });
        var retired = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single().KeyId;

        var due = DateTimeOffset.UnixEpoch + Policy.RotateEvery + TimeSpan.FromDays(1);
        string? first = null;
        Exception? failure = null;
        var firstThread = new Thread(() =>
        {
            moment.Value = due;
            holdNextRead.Value = true;
            try
            {
                first = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).First().KeyId;
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        }) { IsBackground = true };
        firstThread.Start();
        Assert.True(held.Wait(TimeSpan.FromSeconds(5), ct));

        string? second = null;
        var secondThread = new Thread(() =>
        {
            moment.Value = due + TimeSpan.FromSeconds(1);
            try
            {
                second = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).First().KeyId;
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        }) { IsBackground = true };
        secondThread.Start();

        // The second request gets as far as it can while the first is held in its clock read: waiting, or done
        Assert.True(SpinWait.SpinUntil(
            () => secondThread.ThreadState.HasFlag(ThreadState.WaitSleepJoin) ||
                  secondThread.ThreadState.HasFlag(ThreadState.Stopped),
            TimeSpan.FromSeconds(5)));
        release.Set();
        Assert.True(firstThread.Join(TimeSpan.FromSeconds(5)));
        Assert.True(secondThread.Join(TimeSpan.FromSeconds(5)));

        Assert.Null(failure);
        Assert.NotEqual(retired, first);
        Assert.Equal(first, second);
    }

    /// <summary>
    /// A policy that never rotates, given as the longest span there is, keeps serving its key across years
    /// instead of failing on the arithmetic of its own periods.
    /// </summary>
    [Fact]
    public async Task APolicyThatNeverRotates_KeepsItsKeyAcrossYears()
    {
        var time = new FakeTimeProvider();
        var ring = CreateRing(time, Policy with { RotateEvery = TimeSpan.MaxValue });
        var key = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single().KeyId;

        time.Advance(TimeSpan.FromDays(3650));
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        Assert.Equal(key, ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single().KeyId);
    }

    /// <summary>
    /// A policy that never forgets a retired key, given as the longest span there is, keeps the retired key across
    /// two rotations instead of failing on the arithmetic of its own periods.
    /// </summary>
    [Fact]
    public async Task APolicyThatNeverForgets_KeepsTheRetiredKeys()
    {
        var time = new FakeTimeProvider();
        var ring = CreateRing(time, Policy with { KeepRetiredFor = TimeSpan.MaxValue });
        var first = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single().KeyId;

        time.Advance(Policy.RotateEvery * 2.5);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);
        time.Advance(Policy.RotateEvery * 2.5);
        await ring.RefreshAsync(TestContext.Current.CancellationToken);

        var keys = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Select(key => key.KeyId).ToList();
        Assert.Equal(3, keys.Count);
        Assert.Contains(first, keys);
    }

    /// <summary>
    /// A policy that never rotates keeps serving its key when the clock moves backwards, as it does when a host's
    /// clock is corrected.
    /// </summary>
    [Fact]
    public void APolicyThatNeverRotates_KeepsItsKey_WhenTheClockMovesBack()
    {
        var now = DateTimeOffset.UnixEpoch + TimeSpan.FromDays(1);
        var clock = new Mock<TimeProvider>();
        clock.Setup(time => time.GetUtcNow()).Returns(() => now);
        var ring = CreateRing(clock.Object, Policy with { RotateEvery = TimeSpan.MaxValue });
        var key = ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single().KeyId;

        now = DateTimeOffset.UnixEpoch;

        Assert.Equal(key, ring.Get(PublicKeyUsages.Signature, includePrivateKeys: false).Single().KeyId);
    }

    /// <summary>
    /// A policy the ring cannot rotate on stops the host while it registers the ring: a rotation period that is not
    /// positive mints a key for every request, and a negative retention drops a key while it still signs.
    /// </summary>
    [Theory]
    [InlineData(0, 7)]
    [InlineData(-1, 7)]
    [InlineData(30, -1)]
    public void APolicyTheRingCannotRotateOn_IsRefusedAtRegistration(int rotateEveryDays, int keepRetiredForDays)
    {
        var policy = Policy with
        {
            RotateEvery = TimeSpan.FromDays(rotateEveryDays),
            KeepRetiredFor = TimeSpan.FromDays(keepRetiredForDays),
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => new ServiceCollection().AddInMemoryKeyRing(policy));
    }

    /// <summary>
    /// A host whose settings announce a new key for longer than its policy keeps a retired one does not start, rather
    /// than starting and failing every request for a key once the ring is first made.
    /// </summary>
    [Fact]
    public async Task ARetentionShorterThanTheAnnouncementOfANewKey_StopsTheHostAtStartup()
    {
        var services = new ServiceCollection();
        services.Configure<KeyRingOptions>(options => options.KeyRolloverPropagation = TimeSpan.FromDays(30));
        services.AddInMemoryKeyRing(Policy);
        await using var provider = services.BuildServiceProvider();

        await Assert.ThrowsAsync<OptionsValidationException>(() => provider
            .GetRequiredService<IAsyncStartupValidator>()
            .ValidateAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A second registration takes no effect, so its policy does not stop the host: the ring registered first runs.
    /// </summary>
    [Fact]
    public async Task ASecondRegistration_DoesNotStopTheHost_OverAPolicyNoRingRuns()
    {
        var services = new ServiceCollection();
        services.Configure<KeyRingOptions>(options => options.KeyRolloverPropagation = TimeSpan.FromHours(2));
        services.AddInMemoryKeyRing(Policy);
        services.AddInMemoryKeyRing(Policy with { KeepRetiredFor = TimeSpan.FromHours(1) });
        await using var provider = services.BuildServiceProvider();

        await provider
            .GetRequiredService<IAsyncStartupValidator>()
            .ValidateAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// A ring keeping a retired key for less than the time a new key is announced before it signs would drop the
    /// key still signing, so the new one would sign before clients could have fetched it. The ring refuses such a
    /// policy when it is made, the moment it learns how long that announcement is.
    /// </summary>
    [Fact]
    public void ARetentionShorterThanTheAnnouncementOfANewKey_IsRefused()
    {
        var options = Options.Create(new KeyRingOptions { KeyRolloverPropagation = TimeSpan.FromHours(2) });
        var policy = Policy with { KeepRetiredFor = TimeSpan.FromHours(1) };

        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemoryKeyRing(policy, options, new FakeTimeProvider()));
    }
}
