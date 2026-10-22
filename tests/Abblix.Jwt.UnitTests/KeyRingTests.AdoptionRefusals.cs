// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.Jwt.UnitTests;

public sealed partial class KeyRingTests
{
    /// <summary>
    /// An opening judges the adopted keys before any partition opens, so keys adopted where no partition takes them
    /// refuse it with nothing minted, whether the host has started or not.
    /// </summary>
    [Fact]
    public async Task AnOpening_WithKeysAdoptedWhereNoPartitionTakesThem_IsRefusedBeforeAnyKeyIsMinted()
    {
        var adopted = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var (rings, store) = RingsKeeping(
            Keeping(), StubCustodian(_keyEncryptionKey), Adopted(KeyRingOptions.DefaultPartition, [adopted]));

        await Assert.ThrowsAsync<InvalidOperationException>(() => Open(rings, "acme"));

        Assert.Empty(store.Entries);
    }

    /// <summary>
    /// A host without the OIDC server whose settings keep fixed partitions refuses to start with keys adopted into a
    /// partition it never keeps, before its refresh mints a key into any.
    /// </summary>
    [Fact]
    public async Task AHostWithFixedPartitions_RefusesToStart_WithKeysAdoptedIntoAPartitionItNeverKeeps()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new FakeStore();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton(StubCustodian(_keyEncryptionKey));
        services.AddSingleton<IKeyRingStore>(store);
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.ComposeExternalKeyBackends();
        services.Configure<KeyRingOptions>(options => options.Partitions = ["acme"]);
        services.AddKeyRing(new MintedKeys
        {
            KeyEncryptionKeyName = KeyEncryptionKeyName,
            AdoptedKeys = Adopted("initech", [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)]),
        });
        var provider = services.BuildServiceProvider();
        _providers.Add(provider);

        var hosted = provider.GetServices<IHostedService>().ToArray();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            foreach (var starting in hosted.OfType<IHostedLifecycleService>())
                await starting.StartingAsync(ct);

            foreach (var service in hosted)
                await service.StartAsync(ct);
        });

        Assert.Empty(store.Entries);
    }

    /// <summary>
    /// A ring refreshed by host code before the host starts judges the adopted keys before it mints, so keys adopted
    /// into a partition the ring never keeps refuse the refresh with nothing minted.
    /// </summary>
    [Fact]
    public async Task ARefreshBeforeTheStart_WithKeysAdoptedIntoAPartitionTheRingNeverKeeps_IsRefusedBeforeAnyKeyIsMinted()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new FakeStore();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton(StubCustodian(_keyEncryptionKey));
        services.AddSingleton<IKeyRingStore>(store);
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.ComposeExternalKeyBackends();
        services.Configure<KeyRingOptions>(options => options.Partitions = ["acme"]);
        services.AddKeyRing(new MintedKeys
        {
            KeyEncryptionKeyName = KeyEncryptionKeyName,
            AdoptedKeys = Adopted("initech", [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)]),
        });
        var provider = services.BuildServiceProvider();
        _providers.Add(provider);

        var ring = provider.GetRequiredService<IKeyRings>().For("acme");

        await Assert.ThrowsAsync<InvalidOperationException>(() => ring.RefreshAsync(ct));
        Assert.Empty(store.Entries);
    }

    /// <summary>
    /// Keys adopted into the unnamed partition of a ring whose partitions come and go are served by no partition it
    /// opens, so the ring refuses to start with them; keys adopted into a named partition wait for it.
    /// </summary>
    [Fact]
    public void KeysAdoptedIntoTheUnnamedPartition_WhenThePartitionsComeAndGo_RefuseTheStart()
    {
        var adopted = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

        var (minting, _) = RingsKeeping(Keeping(), StubCustodian(_keyEncryptionKey));
        minting.CheckAdoption();

        var (named, _) = RingsKeeping(Keeping(), StubCustodian(_keyEncryptionKey), Adopted("acme", [adopted]));
        named.CheckAdoption();

        var (unnamed, _) = RingsKeeping(
            Keeping(), StubCustodian(_keyEncryptionKey), Adopted(KeyRingOptions.DefaultPartition, [adopted]));
        Assert.Throws<InvalidOperationException>(unnamed.CheckAdoption);
    }

    /// <summary>
    /// Keys adopted into a partition the settings do not keep are served by no partition, so the ring refuses to start
    /// with them; adopted into one they keep, it starts.
    /// </summary>
    [Theory]
    [InlineData("initech")]
    [InlineData(KeyRingOptions.DefaultPartition)]
    public void KeysAdoptedIntoAPartitionTheSettingsDoNotKeep_RefuseTheStart(string partition)
    {
        var adopted = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

        var (kept, _, _) = CreateRings(
            TimeSpan.FromHours(1), new FakeTimeProvider(Now), Adopted("acme", [adopted]), "acme", "globex");
        kept.CheckAdoption();

        var (unkept, _, _) = CreateRings(
            TimeSpan.FromHours(1), new FakeTimeProvider(Now), Adopted(partition, [adopted]), "acme", "globex");
        Assert.Throws<InvalidOperationException>(unkept.CheckAdoption);
    }
}
