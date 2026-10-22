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
    /// One key adopted into two partitions, under any key id and whether the partitions are known at the start or come
    /// and go, refuses the start naming both; a tenant created again under the same id is another partition.
    /// </summary>
    [Theory]
    [InlineData("globex", false, true)]
    [InlineData("globex", true, true)]
    [InlineData("acme~g2", false, true)]
    [InlineData("globex", false, false)]
    public void OneKeyAdoptedIntoTwoPartitions_RefusesTheStart_NamingBoth(
        string other,
        bool otherKeyId,
        bool partitionsFixed)
    {
        var adopted = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var copy = otherKeyId ? adopted with { KeyId = "another" } : adopted;
        var adoptedKeys = new Dictionary<string, IReadOnlyList<JsonWebKey>>
        {
            ["acme"] = [adopted],
            [other] = [copy],
        };

        var parts = partitionsFixed
            ? CreateRings(TimeSpan.FromHours(1), new FakeTimeProvider(Now), adoptedKeys, "acme", other).Item1
            : RingsKeeping(Keeping(), StubCustodian(_keyEncryptionKey), adoptedKeys).Item1;

        var refusal = Assert.Throws<InvalidOperationException>(parts.CheckAdoption);
        Assert.Contains("'acme'", refusal.Message, StringComparison.Ordinal);
        Assert.Contains($"'{other}'", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A key adopted into a partition the ring never keeps and into one it keeps is refused for the partition never
    /// kept, which names the one edit that fixes both, rather than as a key two partitions share.
    /// </summary>
    [Fact]
    public void OneKeyAdoptedIntoAKeptAndAnUnkeptPartition_IsRefusedForTheUnkeptOne()
    {
        var adopted = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
        var adoptedKeys = new Dictionary<string, IReadOnlyList<JsonWebKey>>
        {
            ["acme"] = [adopted],
            ["initech"] = [adopted],
        };

        var (parts, _, _) = CreateRings(TimeSpan.FromHours(1), new FakeTimeProvider(Now), adoptedKeys, "acme");

        var refusal = Assert.Throws<InvalidOperationException>(parts.CheckAdoption);
        Assert.Contains("'initech'", refusal.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("'acme'", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// One key adopted twice into the same partition is a repeat, not sharing, so the ring starts.
    /// </summary>
    [Fact]
    public void OneKeyAdoptedTwiceIntoOnePartition_Starts()
    {
        var adopted = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

        var (parts, _, _) = CreateRings(
            TimeSpan.FromHours(1), new FakeTimeProvider(Now), Adopted("acme", [adopted, adopted]), "acme", "globex");

        parts.CheckAdoption();
    }
}
