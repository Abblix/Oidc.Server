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
}
